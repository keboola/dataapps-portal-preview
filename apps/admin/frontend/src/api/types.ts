/**
 * Response shapes of the admin JSON API (see the API contract), as zod schemas plus inferred types.
 * Schemas are the single definition: components import the inferred types, the client validates
 * every response against the schema.
 */
import { z } from 'zod';

export const appSchema = z.object({
  app_id: z.string(),
  name: z.string(),
  url: z.string(),
  project_id: z.string(),
  config_id: z.string(),
  source: z.string(),
  active: z.boolean(),
  /** "grants": only granted principals; "all_signed_in": anyone the IdP signed in. */
  access: z.enum(['grants', 'all_signed_in']).default('grants'),
});
export type App = z.infer<typeof appSchema>;
export type AppAccess = App['access'];

export const userSchema = z.object({
  email: z.string(),
  display_name: z.string(),
  active: z.boolean(),
});
export type User = z.infer<typeof userSchema>;

export const groupSchema = z.object({
  group_id: z.string(),
  provider: z.string(),
  external_id: z.string(),
  name: z.string(),
});
export type Group = z.infer<typeof groupSchema>;

/** Local group: a flat set of registered users defined inside the suite (not an IdP group). */
export const localGroupSchema = z.object({
  local_group_id: z.string(),
  name: z.string(),
  description: z.string(),
  members: z.array(z.string()),
  member_count: z.number(),
});
export type LocalGroup = z.infer<typeof localGroupSchema>;

export const localGroupsSchema = z.array(localGroupSchema);

/** Compact reference to a local group, as listed on the user detail and the grants page. */
export const localGroupRefSchema = z.object({ local_group_id: z.string(), name: z.string() });
export type LocalGroupRef = z.infer<typeof localGroupRefSchema>;

export const subjectTypeSchema = z.enum(['user', 'group', 'local_group']);
export type SubjectType = z.infer<typeof subjectTypeSchema>;

export const grantSchema = z.object({
  app_id: z.string(),
  subject_type: subjectTypeSchema,
  subject_id: z.string(),
  granted_by: z.string(),
  granted_at: z.string(),
});
export type Grant = z.infer<typeof grantSchema>;

export const decisionSchema = z.object({
  allowed: z.boolean(),
  reason: z.string(),
  matched: z.array(z.string()),
});
export type Decision = z.infer<typeof decisionSchema>;

export const providerSchema = z.object({
  label: z.string(),
  group_id_pattern: z.string(),
  example: z.string(),
});
export type Provider = z.infer<typeof providerSchema>;

const attributesSchema = z.record(z.string(), z.string());

/** Every mutation answers `{message, ...extra}`. */
export const messageSchema = z.object({ message: z.string() });
export type MessageResponse = z.infer<typeof messageSchema>;

export const sessionSchema = z.object({
  user: z.object({ email: z.string(), groups: z.array(z.string()) }),
  app_name: z.string(),
  launcher_url: z.string(),
  switch_user_path: z.string(),
});
export type Session = z.infer<typeof sessionSchema>;

export const overviewSchema = z.object({
  counts: z.object({
    apps: z.number(),
    users: z.number(),
    groups: z.number(),
    grants: z.number(),
    attributes: z.number(),
    // Absent from a backend that predates local groups.
    local_groups: z.number().default(0),
  }),
  apps: z.array(appSchema),
  users: z.array(userSchema),
  groups: z.array(groupSchema),
  user_matrix: z.record(z.string(), z.record(z.string(), decisionSchema)),
  group_grants: z.record(z.string(), z.array(z.string())),
});
export type Overview = z.infer<typeof overviewSchema>;

export const simulationSchema = z.object({
  email: z.string(),
  groups: z.array(z.object({ external_id: z.string(), name: z.string().nullable() })),
  results: z.array(z.object({ app: appSchema, decision: decisionSchema })),
});
export type Simulation = z.infer<typeof simulationSchema>;

export const appsSchema = z.object({ apps: z.array(appSchema) });

export const discoveryInfoSchema = z.object({ available: z.boolean() });

export const discoveryStatusSchema = z.enum(['new', 'registered', 'launcher', 'not_deployed']);
export type DiscoveryStatus = z.infer<typeof discoveryStatusSchema>;

/** How a Data App's own Keboola login is set up, read from its configuration. */
export const authModeSchema = z.enum(['required', 'partial', 'public', 'unknown']);
export type AuthMode = z.infer<typeof authModeSchema>;

export const authProviderSchema = z.object({ id: z.string(), type: z.string(), issuer_url: z.string() });
export type AuthProvider = z.infer<typeof authProviderSchema>;

export const discoveredAppSchema = z.object({
  ds_app_id: z.string(),
  config_id: z.string(),
  project_id: z.string(),
  name: z.string(),
  name_source: z.string(),
  slug: z.string(),
  url: z.string(),
  state: z.string(),
  status: discoveryStatusSchema,
  local_id: z.string(),
  auth_mode: authModeSchema,
  auth_providers: z.array(authProviderSchema),
});
export type DiscoveredApp = z.infer<typeof discoveredAppSchema>;

export const discoveryScanSchema = z.object({ results: z.array(discoveredAppSchema) });

export const discoveryImportSchema = z.object({
  message: z.string().nullable(),
  error: z.string().nullable(),
});
export type DiscoveryImportResult = z.infer<typeof discoveryImportSchema>;

export const userWithAttributesSchema = userSchema.extend({ attributes: attributesSchema });
export type UserWithAttributes = z.infer<typeof userWithAttributesSchema>;

export const usersSchema = z.object({ users: z.array(userWithAttributesSchema) });

export const userDetailSchema = z.object({
  user: userSchema,
  attributes: attributesSchema,
  apps: z.array(appSchema),
  granted: z.array(z.string()),
  local_groups: z.array(localGroupRefSchema).default([]),
});
export type UserDetail = z.infer<typeof userDetailSchema>;

export const userSavedSchema = messageSchema.extend({ email: z.string() });

export const groupsSchema = z.object({
  groups: z.array(groupSchema),
  providers: z.record(z.string(), providerSchema),
});
export type GroupsResponse = z.infer<typeof groupsSchema>;

export const groupDetailSchema = z.object({
  group: groupSchema,
  providers: z.record(z.string(), providerSchema),
  apps: z.array(appSchema),
  granted: z.array(z.string()),
});
export type GroupDetail = z.infer<typeof groupDetailSchema>;

export const grantsSchema = z.object({
  apps: z.array(appSchema),
  grants: z.array(grantSchema),
  users: z.array(userSchema),
  groups: z.array(groupSchema),
  local_groups: z.array(localGroupRefSchema).default([]),
});
export type GrantsResponse = z.infer<typeof grantsSchema>;

/** Raw audit line: the JSON object the audit log wrote; fields depend on `event`. */
export const auditLineSchema = z.record(z.string(), z.unknown());
export type AuditLine = z.infer<typeof auditLineSchema>;

export const auditSchema = z.object({
  lines: z.array(auditLineSchema),
  event: z.string(),
  events: z.array(z.string()),
  tail_lines: z.number(),
});
export type AuditResponse = z.infer<typeof auditSchema>;

/** Bodies of the gate refusals on any /api route (401 not signed in, 403 denied). */
export const deniedBodySchema = z.object({
  detail: z.string(),
  reason: z.string(),
  user: z.object({ email: z.string(), groups: z.array(z.string()) }).optional(),
  // Not in the contract today; rendered as links when a backend sends them.
  launcher_url: z.string().optional(),
  switch_user_path: z.string().optional(),
});
export type DeniedBody = z.infer<typeof deniedBodySchema>;


// ---- dataset security: row access lines, column masks, test as a user -----

export const datasetColumnSchema = z.object({ name: z.string(), type: z.string() });
export type DatasetColumn = z.infer<typeof datasetColumnSchema>;

export const datasetSummarySchema = z.object({
  name: z.string(),
  description: z.string(),
  columns: z.array(datasetColumnSchema),
  show_lines: z.number(),
  hide_lines: z.number(),
  /** Columns that have at least one masking line. */
  masked_columns: z.array(z.string()),
  has_examples: z.boolean(),
});
export type DatasetSummary = z.infer<typeof datasetSummarySchema>;

export const datasetsSchema = z.object({
  datasets: z.array(datasetSummarySchema),
  data_available: z.boolean(),
});
export type DatasetsResponse = z.infer<typeof datasetsSchema>;

/** Who a row line or a mask line applies to; `everyone` is every signed-in user (id ''). */
export const lineSubjectTypeSchema = z.enum(['everyone', 'user', 'local_group', 'group']);
export type LineSubjectType = z.infer<typeof lineSubjectTypeSchema>;

export const lineSubjectSchema = z.object({ type: lineSubjectTypeSchema, id: z.string(), label: z.string() });
export type LineSubject = z.infer<typeof lineSubjectSchema>;

export const conditionOperatorSchema = z.enum([
  'is',
  'is_not',
  'one_of',
  'not_one_of',
  'gt',
  'gte',
  'lt',
  'lte',
  'is_empty',
  'is_not_empty',
]);
export type ConditionOperator = z.infer<typeof conditionOperatorSchema>;

/** A literal as JSON carries it; the server types it from the warehouse column. */
const literalSchema = z.union([z.string(), z.number(), z.boolean()]);

/**
 * `column op value`: exactly one of `value` / `values` / `source`, none for the emptiness
 * operators. `source` is `attribute:<key>` or `email`.
 */
export const conditionSchema = z.object({
  column: z.string(),
  op: conditionOperatorSchema,
  value: literalSchema.optional(),
  values: z.array(literalSchema).optional(),
  source: z.string().optional(),
});
export type Condition = z.infer<typeof conditionSchema>;

export const rowFilterSchema = z.union([
  z.object({ all: z.literal(true) }),
  z.object({ conditions: z.array(conditionSchema) }),
]);
export type RowFilter = z.infer<typeof rowFilterSchema>;

export const rowLineKindSchema = z.enum(['show', 'hide']);
export type RowLineKind = z.infer<typeof rowLineKindSchema>;

export const rowLineSchema = z.object({
  rule_id: z.string(),
  kind: rowLineKindSchema,
  subject: lineSubjectSchema,
  filter: rowFilterSchema,
});
export type RowLine = z.infer<typeof rowLineSchema>;

export const treatmentSchema = z.enum(['clear', 'mask_partial', 'mask_hash', 'hidden']);
export type Treatment = z.infer<typeof treatmentSchema>;

export const maskLineSchema = z.object({
  mask_id: z.string(),
  subject: lineSubjectSchema,
  treatment: treatmentSchema,
});
export type MaskLine = z.infer<typeof maskLineSchema>;

export const datasetDetailSchema = z.object({
  dataset: z.object({ name: z.string(), description: z.string(), columns: z.array(datasetColumnSchema) }),
  rows: z.array(rowLineSchema),
  masks: z.record(z.string(), z.array(maskLineSchema)),
  attributes: z.array(z.string()),
  has_examples: z.boolean(),
  data_available: z.boolean(),
});
export type DatasetDetail = z.infer<typeof datasetDetailSchema>;

export const datasetSavedSchema = datasetDetailSchema.extend({ message: z.string() });

/** `skipped` names example lines that could not be loaded (e.g. an unregistered IdP group). */
export const examplesLoadedSchema = datasetDetailSchema.extend({
  message: z.string(),
  skipped: z.array(z.unknown()),
});

/** PUT body: labels are display-only and ids are optional (a new line has none). */
export type LineSubjectInput = { type: LineSubjectType; id: string };
export type RowLineInput = { rule_id?: string; kind: RowLineKind; subject: LineSubjectInput; filter: RowFilter };
export type MaskLineInput = { mask_id?: string; subject: LineSubjectInput; treatment: Treatment };
export type DatasetSecurityInput = { rows: RowLineInput[]; masks: Record<string, MaskLineInput[]> };

export const columnValuesSchema = z.object({
  values: z.array(z.union([literalSchema, z.null()])),
  truncated: z.boolean(),
});
export type ColumnValues = z.infer<typeof columnValuesSchema>;

export const testLineSchema = z.object({
  rule_id: z.string(),
  kind: rowLineKindSchema,
  applies: z.boolean(),
  reason: z.string(),
  matched_rows: z.number().nullable(),
  warning: z.string().nullable(),
});
export type TestLine = z.infer<typeof testLineSchema>;

export const testColumnSchema = z.object({
  name: z.string(),
  treatment: treatmentSchema,
  mask_id: z.string().nullable(),
  reason: z.string(),
});
export type TestColumn = z.infer<typeof testColumnSchema>;

export const datasetTestSchema = z.object({
  principal: z.object({
    email: z.string(),
    // Shapes not pinned by the contract (ids or {id, name} objects); rendered through `refLabel`.
    local_groups: z.array(z.unknown()),
    idp_groups: z.array(z.unknown()),
    attributes: attributesSchema,
  }),
  accessible: z.boolean(),
  rows: z.object({
    visible: z.number().nullable(),
    total: z.number().nullable(),
    lines: z.array(testLineSchema),
  }),
  columns: z.array(testColumnSchema),
  preview: z
    .object({
      columns: z.array(z.string()),
      rows: z.array(z.array(z.unknown())),
      truncated: z.boolean(),
    })
    .nullable(),
  row_filter: z.string().nullable(),
  data_available: z.boolean(),
});
export type DatasetTest = z.infer<typeof datasetTestSchema>;

export type DatasetTestInput = { email: string; groups: string[] };
