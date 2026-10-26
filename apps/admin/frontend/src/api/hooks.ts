/**
 * TanStack Query hooks over the admin API: one query hook per GET endpoint, one mutation hook
 * per state-changing endpoint.
 *
 * After any successful mutation every data query is invalidated (the session excepted). The
 * pages are small and heavily cross-linked - a grant changes the overview matrices, the grants
 * page, the user and group editors - so a targeted invalidation map would only be a place for
 * bugs to hide. The success toast / error Alert is the caller's job (see
 * components/actionFeedback.tsx and the forms' `setSubmitError`), which keeps these hooks free of UI.
 */
import { keepPreviousData, useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import { apiRequest, segment } from './client';
import {
  appsSchema,
  auditSchema,
  columnValuesSchema,
  datasetDetailSchema,
  datasetSavedSchema,
  datasetsSchema,
  datasetTestSchema,
  discoveryImportSchema,
  discoveryInfoSchema,
  discoveryScanSchema,
  grantsSchema,
  groupDetailSchema,
  groupsSchema,
  localGroupSchema,
  localGroupsSchema,
  messageSchema,
  examplesLoadedSchema,
  overviewSchema,
  sessionSchema,
  simulationSchema,
  userDetailSchema,
  userSavedSchema,
  usersSchema,
  type DatasetSecurityInput,
  type DatasetTestInput,
  type SubjectType,
} from './types';

export const queryKeys = {
  session: ['session'] as const,
  overview: ['overview'] as const,
  apps: ['apps'] as const,
  discovery: ['discovery'] as const,
  users: ['users'] as const,
  user: (email: string) => ['user', email] as const,
  groups: ['groups'] as const,
  group: (groupId: string) => ['group', groupId] as const,
  localGroups: ['local-groups'] as const,
  localGroup: (localGroupId: string) => ['local-group', localGroupId] as const,
  grants: ['grants'] as const,
  datasets: ['datasets'] as const,
  dataset: (name: string) => ['dataset', name] as const,
  datasetValues: (name: string, column: string, q: string) => ['dataset-values', name, column, q] as const,
  datasetTest: (name: string, email: string) => ['dataset-test', name, email] as const,
  audit: (event: string) => ['audit', event] as const,
};

// ---- queries --------------------------------------------------------------

export const useSession = () =>
  useQuery({ queryKey: queryKeys.session, queryFn: ({ signal }) => apiRequest('/session', sessionSchema, { signal }) });

export const useOverview = () =>
  useQuery({ queryKey: queryKeys.overview, queryFn: ({ signal }) => apiRequest('/overview', overviewSchema, { signal }) });

export const useApps = () =>
  useQuery({ queryKey: queryKeys.apps, queryFn: ({ signal }) => apiRequest('/apps', appsSchema, { signal }) });

export const useDiscoveryInfo = () =>
  useQuery({
    queryKey: queryKeys.discovery,
    queryFn: ({ signal }) => apiRequest('/discovery', discoveryInfoSchema, { signal }),
  });

export const useUsers = () =>
  useQuery({ queryKey: queryKeys.users, queryFn: ({ signal }) => apiRequest('/users', usersSchema, { signal }) });

export const useUser = (email: string) =>
  useQuery({
    queryKey: queryKeys.user(email),
    queryFn: ({ signal }) => apiRequest(`/users/${segment(email)}`, userDetailSchema, { signal }),
  });

export const useGroups = () =>
  useQuery({ queryKey: queryKeys.groups, queryFn: ({ signal }) => apiRequest('/groups', groupsSchema, { signal }) });

export const useGroup = (groupId: string) =>
  useQuery({
    queryKey: queryKeys.group(groupId),
    queryFn: ({ signal }) => apiRequest(`/groups/${segment(groupId)}`, groupDetailSchema, { signal }),
  });

export const useLocalGroups = () =>
  useQuery({
    queryKey: queryKeys.localGroups,
    queryFn: ({ signal }) => apiRequest('/local-groups', localGroupsSchema, { signal }),
  });

export const useLocalGroup = (localGroupId: string) =>
  useQuery({
    queryKey: queryKeys.localGroup(localGroupId),
    queryFn: ({ signal }) => apiRequest(`/local-groups/${segment(localGroupId)}`, localGroupSchema, { signal }),
  });

export const useGrants = () =>
  useQuery({ queryKey: queryKeys.grants, queryFn: ({ signal }) => apiRequest('/grants', grantsSchema, { signal }) });

export const useDatasets = () =>
  useQuery({ queryKey: queryKeys.datasets, queryFn: ({ signal }) => apiRequest('/datasets', datasetsSchema, { signal }) });

const datasetQuery = (name: string) => ({
  queryKey: queryKeys.dataset(name),
  queryFn: ({ signal }: { signal: AbortSignal }) =>
    apiRequest(`/datasets/${segment(name)}`, datasetDetailSchema, { signal }),
});

export const useDataset = (name: string) => useQuery(datasetQuery(name));

/** The detail of several datasets at once (the group pages list the lines that name the group). */
export const useDatasetDetails = (names: string[]) => useQueries({ queries: names.map(datasetQuery) });

/**
 * Distinct values of one column for the value suggestions; `q` narrows them server-side (sent only
 * when non-empty). Keeps the previous list while a narrower one loads, so the list does not flicker.
 */
export const useDatasetValues = (name: string, column: string, q: string, enabled: boolean) =>
  useQuery({
    queryKey: queryKeys.datasetValues(name, column, q),
    queryFn: ({ signal }) =>
      apiRequest(
        `/datasets/${segment(name)}/values/${segment(column)}${q ? `?${new URLSearchParams({ q }).toString()}` : ''}`,
        columnValuesSchema,
        { signal },
      ),
    enabled: enabled && column !== '',
    placeholderData: keepPreviousData,
  });

const runDatasetTest = (name: string, input: DatasetTestInput, signal?: AbortSignal) =>
  apiRequest(`/datasets/${segment(name)}/test`, datasetTestSchema, { method: 'POST', body: input, signal });

/**
 * The "Test as" result of one user on every listed dataset, read-only (the user page). A POST, but
 * it changes nothing, so it is cached like a query and refreshed by every data mutation.
 */
export const useDatasetTestsForUser = (email: string, names: string[]) =>
  useQueries({
    queries: names.map((name) => ({
      queryKey: queryKeys.datasetTest(name, email),
      queryFn: ({ signal }: { signal: AbortSignal }) => runDatasetTest(name, { email, groups: [] }, signal),
    })),
  });

/** Audit lines; `event` is '' for all, else one of the server's `events`. */
export const useAudit = (event: string) =>
  useQuery({
    queryKey: queryKeys.audit(event),
    queryFn: ({ signal }) =>
      apiRequest(event ? `/audit?${new URLSearchParams({ event }).toString()}` : '/audit', auditSchema, { signal }),
  });

// ---- mutations ------------------------------------------------------------

/** Invalidate every data query; the session is identity, not data, and stays cached. */
function useInvalidateData() {
  const queryClient = useQueryClient();
  return () =>
    queryClient.invalidateQueries({ predicate: (query) => query.queryKey[0] !== queryKeys.session[0] });
}

/** Mutation that invalidates all data on success. */
function useDataMutation<TVariables, TResult>(mutationFn: (variables: TVariables) => Promise<TResult>) {
  const invalidate = useInvalidateData();
  return useMutation({
    mutationFn,
    onSuccess: async () => {
      await invalidate();
    },
  });
}

export type SimulateInput = { email: string; groups: string[]; extra: string };

/** The simulator reads state and changes nothing, so it does not invalidate. */
export const useSimulate = () =>
  useMutation({
    mutationFn: (input: SimulateInput) => apiRequest('/simulate', simulationSchema, { method: 'POST', body: input }),
  });

/** "Test as" on the dataset editor: reads state, changes nothing, so it does not invalidate. */
export const useDatasetTest = (name: string) =>
  useMutation({ mutationFn: (input: DatasetTestInput) => runDatasetTest(name, input) });

/** Replaces every row line and mask of one dataset as a unit; answers with the saved state. */
export const useSaveDatasetSecurity = (name: string) =>
  useDataMutation((input: DatasetSecurityInput) =>
    apiRequest(`/datasets/${segment(name)}`, datasetSavedSchema, { method: 'PUT', body: input }),
  );

/** Loads the policy file's example rules into an empty dataset (409 when it has lines). */
export const useLoadDatasetExamples = (name: string) =>
  useDataMutation(() =>
    apiRequest(`/datasets/${segment(name)}/load-examples`, examplesLoadedSchema, { method: 'POST' }),
  );

export type AppInput = {
  app_id: string;
  name: string;
  url: string;
  project_id: string;
  config_id: string;
  active: boolean;
  access: 'grants' | 'all_signed_in';
};

export const useSaveApp = () =>
  useDataMutation((input: AppInput) => apiRequest('/apps', messageSchema, { method: 'POST', body: input }));

export const useToggleApp = () =>
  useDataMutation((appId: string) =>
    apiRequest(`/apps/${segment(appId)}/toggle`, messageSchema, { method: 'POST' }),
  );

export const useDeleteApp = () =>
  useDataMutation((appId: string) => apiRequest(`/apps/${segment(appId)}`, messageSchema, { method: 'DELETE' }));

/** A scan reads the platform and changes nothing locally; results live in the page's state. */
export const useDiscoveryScan = () =>
  useMutation({ mutationFn: () => apiRequest('/discovery/scan', discoveryScanSchema, { method: 'POST' }) });

export type DiscoveryImportItem = { ds_app_id: string; local_id: string; name: string };

export const useDiscoveryImport = () =>
  useDataMutation((items: DiscoveryImportItem[]) =>
    apiRequest('/discovery/import', discoveryImportSchema, { method: 'POST', body: { items } }),
  );

export const useCreateUser = () =>
  useDataMutation((input: { email: string; display_name: string }) =>
    apiRequest('/users', messageSchema, { method: 'POST', body: input }),
  );

export const useToggleUser = () =>
  useDataMutation((email: string) =>
    apiRequest(`/users/${segment(email)}/toggle`, messageSchema, { method: 'POST' }),
  );

export const useDeleteUser = () =>
  useDataMutation((email: string) => apiRequest(`/users/${segment(email)}`, messageSchema, { method: 'DELETE' }));

export type UserUpdateInput = {
  email: string;
  new_email: string;
  display_name: string;
  active: boolean;
  app_ids: string[];
};

export const useUpdateUser = () =>
  useDataMutation(({ email, ...body }: UserUpdateInput) =>
    apiRequest(`/users/${segment(email)}`, userSavedSchema, { method: 'PUT', body }),
  );

export const useSetAttribute = () =>
  useDataMutation(({ email, key, value }: { email: string; key: string; value: string }) =>
    apiRequest(`/users/${segment(email)}/attributes/${segment(key)}`, messageSchema, {
      method: 'PUT',
      body: { value },
    }),
  );

export const useRemoveAttribute = () =>
  useDataMutation(({ email, key }: { email: string; key: string }) =>
    apiRequest(`/users/${segment(email)}/attributes/${segment(key)}`, messageSchema, { method: 'DELETE' }),
  );

export type GroupInput = { provider: string; external_id: string; name: string };

export const useCreateGroup = () =>
  useDataMutation((input: GroupInput) => apiRequest('/groups', messageSchema, { method: 'POST', body: input }));

export const useUpdateGroup = () =>
  useDataMutation(({ group_id, ...body }: GroupInput & { group_id: string; app_ids: string[] }) =>
    apiRequest(`/groups/${segment(group_id)}`, messageSchema, { method: 'PUT', body }),
  );

export const useDeleteGroup = () =>
  useDataMutation((groupId: string) =>
    apiRequest(`/groups/${segment(groupId)}`, messageSchema, { method: 'DELETE' }),
  );

export type LocalGroupInput = { local_group_id: string; name: string; description: string };

export const useCreateLocalGroup = () =>
  useDataMutation((input: LocalGroupInput) =>
    apiRequest('/local-groups', localGroupSchema, { method: 'POST', body: input }),
  );

export const useUpdateLocalGroup = () =>
  useDataMutation(({ local_group_id, ...body }: LocalGroupInput) =>
    apiRequest(`/local-groups/${segment(local_group_id)}`, localGroupSchema, { method: 'PUT', body }),
  );

export const useDeleteLocalGroup = () =>
  useDataMutation((localGroupId: string) =>
    apiRequest(`/local-groups/${segment(localGroupId)}`, messageSchema, { method: 'DELETE' }),
  );

export const useAddLocalGroupMember = () =>
  useDataMutation(({ localGroupId, email }: { localGroupId: string; email: string }) =>
    apiRequest(`/local-groups/${segment(localGroupId)}/members/${segment(email)}`, messageSchema, {
      method: 'PUT',
    }),
  );

export const useRemoveLocalGroupMember = () =>
  useDataMutation(({ localGroupId, email }: { localGroupId: string; email: string }) =>
    apiRequest(`/local-groups/${segment(localGroupId)}/members/${segment(email)}`, messageSchema, {
      method: 'DELETE',
    }),
  );

export type GrantInput = { app_id: string; subject_type: SubjectType; subject_id: string };

export const useCreateGrant = () =>
  useDataMutation((input: GrantInput) => apiRequest('/grants', messageSchema, { method: 'POST', body: input }));

export const useRevokeGrant = () =>
  useDataMutation((input: GrantInput) =>
    apiRequest('/grants/revoke', messageSchema, { method: 'POST', body: input }),
  );
