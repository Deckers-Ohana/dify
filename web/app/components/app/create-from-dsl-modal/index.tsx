'use client'

import type { MouseEventHandler } from 'react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { useContext } from 'use-context-selector'
import { useTranslation } from 'react-i18next'
import { RiCloseLine, RiCommandLine, RiCornerDownLeftLine } from '@remixicon/react'
import { useDebounceFn, useKeyPress } from 'ahooks'
import Uploader from './uploader'
import Button from '@/app/components/base/button'
import Input from '@/app/components/base/input'
import Modal from '@/app/components/base/modal'
import { ToastContext } from '@/app/components/base/toast'
import {
  importDSL,
  importDSLConfirm,
} from '@/service/apps'
import {
  DSLImportMode,
  DSLImportStatus,
} from '@/models/app'
import { useAppContext } from '@/context/app-context'
import { useProviderContext } from '@/context/provider-context'
import AppsFull from '@/app/components/billing/apps-full-in-dialog'
import { NEED_REFRESH_APP_LIST_KEY } from '@/config'
import { getRedirection } from '@/utils/app-redirection'
import cn from '@/utils/classnames'
import { usePluginDependencies } from '@/app/components/workflow/plugin-dependency/hooks'
import { noop } from 'lodash-es'

type CreateFromDSLModalProps = {
  show: boolean
  onSuccess?: () => void
  onClose: () => void
  activeTab?: string
  dslUrl?: string
  droppedFile?: File
}

export enum CreateFromDSLModalTab {
  FROM_FILE = 'from-file',
  FROM_URL = 'from-url',
}

const CreateFromDSLModal = ({ show, onSuccess, onClose, activeTab = CreateFromDSLModalTab.FROM_FILE, dslUrl = '', droppedFile }: CreateFromDSLModalProps) => {
  const { push } = useRouter()
  const { t } = useTranslation()
  const { notify } = useContext(ToastContext)
  const [currentFile, setDSLFile] = useState<File | undefined>(droppedFile)
  const [fileContent, setFileContent] = useState<string>()
  const [currentTab, setCurrentTab] = useState(activeTab)
  const [dslUrlValue, setDslUrlValue] = useState(dslUrl)
  const [showErrorModal, setShowErrorModal] = useState(false)
  const [versions, setVersions] = useState<{ importedVersion: string; systemVersion: string }>()
  const [importId, setImportId] = useState<string>()
  const { handleCheckPluginDependencies } = usePluginDependencies()

  const readFile = (file: File) => {
    const reader = new FileReader()
    reader.onload = function (event) {
      const content = event.target?.result
      setFileContent(content as string)
    }
    reader.readAsText(file)
  }

  const handleFile = (file?: File) => {
    setDSLFile(file)
    if (file)
      readFile(file)
    if (!file)
      setFileContent('')
  }

  const { isCurrentWorkspaceEditor } = useAppContext()
  const { plan, enableBilling } = useProviderContext()
  const isAppsFull = (enableBilling && plan.usage.buildApps >= plan.total.buildApps)

  const isCreatingRef = useRef(false)

  useEffect(() => {
    if (droppedFile)
      handleFile(droppedFile)
  }, [droppedFile])

  const onCreate: MouseEventHandler = async () => {
    if (currentTab === CreateFromDSLModalTab.FROM_FILE && !currentFile)
      return
    if (currentTab === CreateFromDSLModalTab.FROM_URL && !dslUrlValue)
      return
    if (isCreatingRef.current)
      return
    isCreatingRef.current = true
    try {
      let response

      if (currentTab === CreateFromDSLModalTab.FROM_FILE) {
        response = await importDSL({
          mode: DSLImportMode.YAML_CONTENT,
          yaml_content: fileContent || '',
        })
      }
      if (currentTab === CreateFromDSLModalTab.FROM_URL) {
        response = await importDSL({
          mode: DSLImportMode.YAML_URL,
          yaml_url: dslUrlValue || '',
        })
      }

      if (!response)
        return
      const { id, status, app_id, app_mode, imported_dsl_version, current_dsl_version } = response
      if (status === DSLImportStatus.COMPLETED || status === DSLImportStatus.COMPLETED_WITH_WARNINGS) {
        if (onSuccess)
          onSuccess()
        if (onClose)
          onClose()

        notify({
          type: status === DSLImportStatus.COMPLETED ? 'success' : 'warning',
          message: t(status === DSLImportStatus.COMPLETED ? 'app.newApp.appCreated' : 'app.newApp.caution'),
          children: status === DSLImportStatus.COMPLETED_WITH_WARNINGS && t('app.newApp.appCreateDSLWarning'),
        })
        localStorage.setItem(NEED_REFRESH_APP_LIST_KEY, '1')
        if (app_id)
          await handleCheckPluginDependencies(app_id)
        getRedirection(isCurrentWorkspaceEditor, { id: app_id!, mode: app_mode }, push)
      }
      else if (status === DSLImportStatus.PENDING) {
        setVersions({
          importedVersion: imported_dsl_version ?? '',
          systemVersion: current_dsl_version ?? '',
        })
        if (onClose)
          onClose()
        setTimeout(() => {
          setShowErrorModal(true)
        }, 300)
        setImportId(id)
      }
      else {
        notify({ type: 'error', message: t('app.newApp.appCreateFailed') })
      }
    }
    // eslint-disable-next-line unused-imports/no-unused-vars
    catch (e) {
      notify({ type: 'error', message: t('app.newApp.appCreateFailed') })
    }
    isCreatingRef.current = false
  }

  const { run: handleCreateApp } = useDebounceFn(onCreate, { wait: 300 })

  useKeyPress(['meta.enter', 'ctrl.enter'], () => {
    if (show && !isAppsFull && ((currentTab === CreateFromDSLModalTab.FROM_FILE && currentFile) || (currentTab === CreateFromDSLModalTab.FROM_URL && dslUrlValue)))
      handleCreateApp()
  })

  useKeyPress('esc', () => {
    if (show && !showErrorModal)
      onClose()
  })

  const onDSLConfirm: MouseEventHandler = async () => {
    try {
      if (!importId)
        return
      const response = await importDSLConfirm({
        import_id: importId,
      })

      const { status, app_id, app_mode } = response

      if (status === DSLImportStatus.COMPLETED) {
        if (onSuccess)
          onSuccess()
        if (onClose)
          onClose()

        notify({
          type: 'success',
          message: t('app.newApp.appCreated'),
        })
        if (app_id)
          await handleCheckPluginDependencies(app_id)
        localStorage.setItem(NEED_REFRESH_APP_LIST_KEY, '1')
        getRedirection(isCurrentWorkspaceEditor, { id: app_id!, mode: app_mode }, push)
      }
      else if (status === DSLImportStatus.FAILED) {
        notify({ type: 'error', message: t('app.newApp.appCreateFailed') })
      }
    }
    // eslint-disable-next-line unused-imports/no-unused-vars
    catch (e) {
      notify({ type: 'error', message: t('app.newApp.appCreateFailed') })
    }
  }

  const tabs = [
    {
      key: CreateFromDSLModalTab.FROM_FILE,
      label: t('app.importFromDSLFile'),
    },
    {
      key: CreateFromDSLModalTab.FROM_URL,
      label: t('app.importFromDSLUrl'),
    },
  ]

  const buttonDisabled = useMemo(() => {
    if (isAppsFull)
      return true
    if (currentTab === CreateFromDSLModalTab.FROM_FILE)
      return !currentFile
    if (currentTab === CreateFromDSLModalTab.FROM_URL)
      return !dslUrlValue
    return false
  }, [isAppsFull, currentTab, currentFile, dslUrlValue])

  return (
    <>
      <Modal
        className='w-[520px] rounded-2xl border-[0.5px] border-components-panel-border bg-components-panel-bg p-0 shadow-xl'
        isShow={show}
        onClose={noop}
      >
        <div className='title-2xl-semi-bold flex items-center justify-between pb-3 pl-6 pr-5 pt-6 text-text-primary'>
          {t('app.importFromDSL')}
          <div
            className='flex h-8 w-8 cursor-pointer items-center'
            onClick={() => onClose()}
          >
            <RiCloseLine className='h-5 w-5 text-text-tertiary' />
          </div>
        </div>
        <div className='system-md-semibold flex h-9 items-center space-x-6 border-b border-divider-subtle px-6 text-text-tertiary'>
          {
            tabs.map(tab => (
              <div
                key={tab.key}
                className={cn(
                  'relative flex h-full cursor-pointer items-center',
                  currentTab === tab.key && 'text-text-primary',
                )}
                onClick={() => setCurrentTab(tab.key)}
              >
                {tab.label}
                {
                  currentTab === tab.key && (
                    <div className='absolute bottom-0 h-[2px] w-full bg-util-colors-blue-brand-blue-brand-600'></div>
                  )
                }
              </div>
            ))
          }
        </div>
        <div className='px-6 py-4'>
          {
            currentTab === CreateFromDSLModalTab.FROM_FILE && (
              <Uploader
                className='mt-0'
                file={currentFile}
                updateFile={handleFile}
              />
            )
          }
          {
            currentTab === CreateFromDSLModalTab.FROM_URL && (
              <div>
                <div className='system-md-semibold mb-1 text-text-secondary'>DSL URL</div>
                <Input
                  placeholder={t('app.importFromDSLUrlPlaceholder') || ''}
                  value={dslUrlValue}
                  onChange={e => setDslUrlValue(e.target.value)}
                />
              </div>
            )
          }
        </div>
        {isAppsFull && (
          <div className='px-6'>
            <AppsFull className='mt-0' loc='app-create-dsl' />
          </div>
        )}
        <div className='flex justify-end px-6 py-5'>
          <Button className='mr-2' onClick={onClose}>{t('app.newApp.Cancel')}</Button>
          <Button
            disabled={buttonDisabled}
            variant="primary"
            onClick={handleCreateApp}
            className="gap-1"
          >
            <span>{t('app.newApp.Create')}</span>
            <div className='flex gap-0.5'>
              <RiCommandLine size={14} className='system-kbd rounded-sm bg-components-kbd-bg-white p-0.5' />
              <RiCornerDownLeftLine size={14} className='system-kbd rounded-sm bg-components-kbd-bg-white p-0.5' />
            </div>
          </Button>
        </div>
      </Modal>
      <Modal
        isShow={showErrorModal}
        onClose={() => setShowErrorModal(false)}
        className='w-[480px]'
      >
        <div className='flex flex-col items-start gap-2 self-stretch pb-4'>
          <div className='title-2xl-semi-bold text-text-primary'>{t('app.newApp.appCreateDSLErrorTitle')}</div>
          <div className='system-md-regular flex grow flex-col text-text-secondary'>
            <div>{t('app.newApp.appCreateDSLErrorPart1')}</div>
            <div>{t('app.newApp.appCreateDSLErrorPart2')}</div>
            <br />
            <div>{t('app.newApp.appCreateDSLErrorPart3')}<span className='system-md-medium'>{versions?.importedVersion}</span></div>
            <div>{t('app.newApp.appCreateDSLErrorPart4')}<span className='system-md-medium'>{versions?.systemVersion}</span></div>
          </div>
        </div>
        <div className='flex items-start justify-end gap-2 self-stretch pt-6'>
          <Button variant='secondary' onClick={() => setShowErrorModal(false)}>{t('app.newApp.Cancel')}</Button>
          <Button variant='primary' destructive onClick={onDSLConfirm}>{t('app.newApp.Confirm')}</Button>
        </div>
      </Modal>
    </>
  )
}

export default CreateFromDSLModal
