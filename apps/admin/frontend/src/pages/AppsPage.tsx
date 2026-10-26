/**
 * Apps: the registry of Data Apps the gate knows. Create and edit in a modal (upsert on the
 * server; editing keeps the app's source), activate / deactivate, delete with its grants.
 * An app can be opened to everyone the IdP signs in, so nobody has to grant the whole company.
 */
import { useState } from 'react';
import { z } from 'zod';
import {
  Button,
  Card,
  EmptyState,
  Link,
  Modal,
  PageHeader,
  PageLayout,
  setSubmitError,
  Table,
  toast,
  useAppForm,
} from '@keboola/design';
import { Pencil, Plus, Power } from '@keboola/design/icons';
import { errorMessage } from '../api/client';
import { useApps, useDeleteApp, useSaveApp, useToggleApp } from '../api/hooks';
import type { App } from '../api/types';
import { ActionFeedbackScope, usePageAction } from '../components/actionFeedback';
import { AccessBadge, ActiveBadge } from '../components/Badges';
import { Code, NameWithId } from '../components/Code';
import { ConfirmButton } from '../components/ConfirmButton';
import { LoadError, PageSkeleton } from '../components/PageStates';
import { config } from '../config';

const FORM_ID = 'app-form';

const appIdSchema = z
  .string()
  .regex(config.patterns.appId, 'Lowercase letters, digits, "-" and "_"; starts with a letter or digit; up to 64.');
const nameSchema = z.string().trim().min(1, 'Enter a name.');

type EditorState = { mode: 'create' } | { mode: 'edit'; app: App } | null;

function AppForm({ editing, onDone }: { editing: App | null; onDone: () => void }) {
  const save = useSaveApp();
  const form = useAppForm({
    defaultValues: {
      app_id: editing?.app_id ?? '',
      name: editing?.name ?? '',
      url: editing?.url ?? '',
      project_id: editing?.project_id ?? '',
      config_id: editing?.config_id ?? '',
      active: editing ? editing.active : true,
      all_signed_in: editing?.access === 'all_signed_in',
    },
    canSubmitWhenInvalid: true,
    onSubmit: async ({ value, formApi }) => {
      const { all_signed_in: allSignedIn, ...rest } = value;
      try {
        const result = await save.mutateAsync({ ...rest, access: allSignedIn ? 'all_signed_in' : 'grants' });
        toast.success(result.message);
        onDone();
      } catch (error) {
        setSubmitError(formApi, errorMessage(error));
      }
    },
  });

  return (
    <>
      <Modal.Body>
        <form.AppForm>
          <form.FormBody id={FORM_ID}>
            {editing ? (
              <p className="tw:text-sm">
                App ID <Code>{editing.app_id}</Code>
              </p>
            ) : (
              <form.AppField name="app_id" validators={{ onBlur: appIdSchema, onSubmit: appIdSchema }}>
                {(field) => <field.TextField label="App ID" required placeholder="sales" />}
              </form.AppField>
            )}
            <form.AppField name="name" validators={{ onBlur: nameSchema, onSubmit: nameSchema }}>
              {(field) => <field.TextField label="Name" required />}
            </form.AppField>
            <form.AppField name="url">
              {(field) => <field.TextField label="URL" placeholder="https://…" />}
            </form.AppField>
            <div className="tw:grid tw:gap-4 tw:md:grid-cols-2">
              <form.AppField name="project_id">{(field) => <field.TextField label="Project ID" />}</form.AppField>
              <form.AppField name="config_id">{(field) => <field.TextField label="Config ID" />}</form.AppField>
            </div>
            <form.AppField name="active">{(field) => <field.SwitchField>Active</field.SwitchField>}</form.AppField>
            <form.AppField name="all_signed_in">
              {(field) => <field.SwitchField>Open to everyone signed in</field.SwitchField>}
            </form.AppField>
            <p className="tw:text-sm tw:text-muted-foreground">
              Anyone the identity provider signs in may open the app, without a grant. Deactivated users stay
              blocked. Leave off to allow only users and groups granted on the Grants page.
            </p>
            <form.SubmitErrorAlert />
          </form.FormBody>
        </form.AppForm>
      </Modal.Body>
      <Modal.Footer>
        <Modal.Close asChild>
          <Button type="button" variant="secondary">
            Cancel
          </Button>
        </Modal.Close>
        <form.AppForm>
          <form.SubmitButton form={FORM_ID}>{editing ? 'Save' : 'Create'}</form.SubmitButton>
        </form.AppForm>
      </Modal.Footer>
    </>
  );
}

function AppRow({ app, onEdit }: { app: App; onEdit: () => void }) {
  const toggle = useToggleApp();
  const remove = useDeleteApp();
  const runAction = usePageAction();
  return (
    <Table.Row>
      <Table.Cell>
        <NameWithId name={app.name} id={app.app_id} />
      </Table.Cell>
      <Table.Cell>
        {app.url ? (
          <Link href={app.url}>{app.url}</Link>
        ) : (
          <span className="tw:text-muted-foreground">none</span>
        )}
      </Table.Cell>
      <Table.Cell>
        <Code>{app.project_id}</Code> / <Code>{app.config_id}</Code>
      </Table.Cell>
      <Table.Cell>{app.source}</Table.Cell>
      <Table.Cell>
        <div className="tw:flex tw:flex-wrap tw:gap-1">
          <ActiveBadge active={app.active} />
          <AccessBadge access={app.access} />
        </div>
      </Table.Cell>
      <Table.Cell>
        <div className="tw:flex tw:flex-wrap tw:justify-end tw:gap-2">
          <Button variant="outline" size="small" onClick={onEdit} aria-label={`Edit ${app.app_id}`}>
            <Pencil className="tw:size-4" /> Edit
          </Button>
          <Button
            variant="outline"
            size="small"
            isLoading={toggle.isPending}
            disabled={toggle.isPending}
            aria-label={`${app.active ? 'Deactivate' : 'Activate'} ${app.app_id}`}
            onClick={() => void runAction(() => toggle.mutateAsync(app.app_id))}
          >
            <Power className="tw:size-4" /> {app.active ? 'Deactivate' : 'Activate'}
          </Button>
          <ConfirmButton
            label="Delete"
            ariaLabel={`Delete ${app.app_id}`}
            title={`Delete ${app.app_id}?`}
            confirmLabel="Delete app"
            onConfirm={() => runAction(() => remove.mutateAsync(app.app_id))}
          >
            Deletes the app and all its grants. This cannot be undone.
          </ConfirmButton>
        </div>
      </Table.Cell>
    </Table.Row>
  );
}

export function AppsPage() {
  const apps = useApps();
  const [editor, setEditor] = useState<EditorState>(null);
  const editing = editor?.mode === 'edit' ? editor.app : null;

  return (
    <PageLayout>
      <PageLayout.Header>
        <PageHeader.Index
          title="Apps"
          action={
            <Button onClick={() => setEditor({ mode: 'create' })}>
              <Plus className="tw:size-4" /> Register an app
            </Button>
          }
        />
      </PageLayout.Header>
      <PageLayout.Content>
        <ActionFeedbackScope>
            {apps.isPending ? (
              <PageSkeleton />
            ) : apps.isError ? (
              <LoadError error={apps.error} onRetry={() => void apps.refetch()} />
            ) : (
              <Card bordered padding="none">
                <Card.Content>
                  {apps.data.apps.length === 0 ? (
                    <EmptyState variant="compact">
                      <EmptyState.Title>No apps registered.</EmptyState.Title>
                      <EmptyState.Actions>
                        <Button size="small" onClick={() => setEditor({ mode: 'create' })}>
                          Register an app
                        </Button>
                      </EmptyState.Actions>
                    </EmptyState>
                  ) : (
                    <Table aria-label="Apps">
                      <Table.Header>
                        <Table.Row>
                          <Table.Head>App</Table.Head>
                          <Table.Head>URL</Table.Head>
                          <Table.Head>Project / config</Table.Head>
                          <Table.Head>Source</Table.Head>
                          <Table.Head>Status</Table.Head>
                          <Table.Head>
                            <span className="tw:sr-only">Actions</span>
                          </Table.Head>
                        </Table.Row>
                      </Table.Header>
                      <Table.Body>
                        {apps.data.apps.map((app) => (
                          <AppRow key={app.app_id} app={app} onEdit={() => setEditor({ mode: 'edit', app })} />
                        ))}
                      </Table.Body>
                    </Table>
                  )}
                </Card.Content>
              </Card>
            )}
        </ActionFeedbackScope>
        <Modal open={editor !== null} onOpenChange={(open) => !open && setEditor(null)}>
          <Modal.Content size="medium">
            <Modal.Header>{editing ? `Edit ${editing.app_id}` : 'Register an app'}</Modal.Header>
            {editor && (
              <AppForm
                key={editing?.app_id ?? 'new'}
                editing={editing}
                onDone={() => setEditor(null)}
              />
            )}
          </Modal.Content>
        </Modal>
      </PageLayout.Content>
    </PageLayout>
  );
}
