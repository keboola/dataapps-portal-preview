import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { APP_HR, APP_SALES } from '../test/fixtures';
import { mockFetch, renderApp, SESSION } from '../test/utils';

describe('AppsPage', () => {
  it('registers an app from the modal', async () => {
    const { calls } = mockFetch({
      'GET /api/session': { body: SESSION },
      'GET /api/apps': { body: { apps: [APP_SALES] } },
      'POST /api/apps': { body: { message: "App 'finance' saved." } },
    });
    const user = userEvent.setup();
    renderApp('/apps');
    await user.click(await screen.findByRole('button', { name: /Register an app/ }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText(/App ID/), 'finance');
    await user.type(within(dialog).getByLabelText(/^Name/), 'Finance');
    await user.click(within(dialog).getByRole('button', { name: 'Create' }));
    expect(await screen.findByText("App 'finance' saved.")).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      app_id: 'finance',
      name: 'Finance',
      url: '',
      project_id: '',
      config_id: '',
      active: true,
      access: 'grants',
    });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('opens an app to everyone signed in and marks it in the list', async () => {
    const { calls } = mockFetch({
      'GET /api/session': { body: SESSION },
      'GET /api/apps': { body: { apps: [APP_SALES, { ...APP_HR, access: 'all_signed_in' }] } },
      'POST /api/apps': { body: { message: "App 'sales' saved." } },
    });
    const user = userEvent.setup();
    renderApp('/apps');
    const hrRow = (await screen.findByRole('button', { name: 'Edit hr' })).closest('tr')!;
    expect(within(hrRow).getByText('everyone signed in')).toBeInTheDocument();
    const salesRow = screen.getByRole('button', { name: 'Edit sales' }).closest('tr')!;
    expect(within(salesRow).queryByText('everyone signed in')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Edit sales' }));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('switch', { name: /Open to everyone signed in/ }));
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    expect(await screen.findByText("App 'sales' saved.")).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'POST')?.body).toMatchObject({ app_id: 'sales', access: 'all_signed_in' });
  });

  it('rejects an app ID outside the pattern without calling the server', async () => {
    const { calls } = mockFetch({
      'GET /api/session': { body: SESSION },
      'GET /api/apps': { body: { apps: [] } },
    });
    const user = userEvent.setup();
    renderApp('/apps');
    await user.click(await screen.findByRole('button', { name: /Register an app/ }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText(/App ID/), 'Bad ID');
    await user.type(within(dialog).getByLabelText(/^Name/), 'x');
    await user.click(within(dialog).getByRole('button', { name: 'Create' }));
    expect(await within(dialog).findByText(/Lowercase letters/)).toBeInTheDocument();
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });

  it('edits an app keeping its ID', async () => {
    const { calls } = mockFetch({
      'GET /api/session': { body: SESSION },
      'GET /api/apps': { body: { apps: [APP_HR, APP_SALES] } },
      'POST /api/apps': { body: { message: "App 'hr' saved." } },
    });
    const user = userEvent.setup();
    renderApp('/apps');
    await user.click(await screen.findByRole('button', { name: 'Edit hr' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).queryByLabelText(/App ID/)).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    expect(await screen.findByText("App 'hr' saved.")).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'POST')?.body).toMatchObject({ app_id: 'hr', active: false, access: 'grants' });
  });

  it('toggles and deletes an app', async () => {
    const { calls } = mockFetch({
      'GET /api/session': { body: SESSION },
      'GET /api/apps': { body: { apps: [APP_SALES] } },
      'POST /api/apps/sales/toggle': { body: { message: "App 'sales' deactivated." } },
      'DELETE /api/apps/sales': { body: { message: "App 'sales' deleted with its grants." } },
    });
    const user = userEvent.setup();
    renderApp('/apps');
    await user.click(await screen.findByRole('button', { name: 'Deactivate sales' }));
    expect(await screen.findByText("App 'sales' deactivated.")).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Delete sales' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Delete app' }));
    expect(await screen.findByText("App 'sales' deleted with its grants.")).toBeInTheDocument();
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual(
      expect.arrayContaining(['POST /api/apps/sales/toggle', 'DELETE /api/apps/sales']),
    );
  });
});
