#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const MANIFEST_SCHEMA_URL = new URL("../contracts/dataset-manifest.schema.json", import.meta.url);
const POLICY_SCHEMA_URL = new URL("../contracts/source-policy.schema.json", import.meta.url);
const CONTENT_CONTRACT_URL = new URL("../contracts/data-content-v1.json", import.meta.url);
const SOURCE_POLICY_URL = new URL("../docs/licensing/source-policy.json", import.meta.url);
const FIXTURES_URL = new URL("../contracts/fixtures/dataset-manifest.cases.json", import.meta.url);
const POLICY_FIXTURES_URL = new URL("../contracts/fixtures/source-policy.cases.json", import.meta.url);

const REVISION_PATTERN = /^[0-9a-f]{40}$/;
const REVIEWED_VERSION_BASELINES = Object.freeze({
  "1:1.0.0": Object.freeze({
    content_contract_sha256: "8af4d8a738b7a763599d4958b6ce347b41881a310dccc1223a296bfbe76c4047",
    source_policy_sha256: "aac832b0c189106901312998074bd4390d3e7c05d3d65eb72297fb5e0677a538",
  }),
});
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const pointerPart = (value) => String(value).replaceAll("~", "~0").replaceAll("/", "~1");
const childPath = (path, key) => `${path}/${pointerPart(key)}`;
const stableStringify = (value) => {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (isObject(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
};
const deepEqual = (left, right) => stableStringify(left) === stableStringify(right);
const sortedUnique = (values) => [...new Set(values)].sort();
const duplicates = (values) => {
  const seen = new Set();
  return sortedUnique(values.filter((value) => (seen.has(value) ? true : !seen.add(value))));
};

const isCalendarDate = (value) => {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) return false;
  const date = new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])));
  return date.toISOString().slice(0, 10) === value;
};
const isDateTime = (value) => typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value) && !Number.isNaN(Date.parse(value));
const isUri = (value) => {
  try {
    const parsed = new URL(value);
    return Boolean(parsed.protocol && parsed.hostname);
  } catch {
    return false;
  }
};
const isType = (value, type) => ({
  array: Array.isArray(value),
  boolean: typeof value === "boolean",
  integer: Number.isInteger(value),
  null: value === null,
  number: typeof value === "number" && Number.isFinite(value),
  object: isObject(value),
  string: typeof value === "string",
})[type] ?? false;
const resolveRef = (schema, ref) => ref.slice(2).split("/").map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~")).reduce((node, part) => node?.[part], schema);

const validateSchemaNode = (value, node, root, path = "") => {
  if (node === true) return [];
  if (node === false) return [{ path, keyword: "falseSchema", message: "value is forbidden" }];
  if (!isObject(node)) throw new Error(`Invalid schema node at ${path || "/"}`);
  if (node.$ref) {
    if (!node.$ref.startsWith("#/")) throw new Error(`Only local JSON Schema references are supported: ${node.$ref}`);
    const target = resolveRef(root, node.$ref);
    if (!target) throw new Error(`Unresolved JSON Schema reference: ${node.$ref}`);
    return validateSchemaNode(value, target, root, path);
  }
  const issues = [];
  const add = (keyword, message, issuePath = path) => issues.push({ path: issuePath, keyword, message });
  if (node.oneOf) {
    if (node.oneOf.filter((branch) => validateSchemaNode(value, branch, root, path).length === 0).length !== 1) add("oneOf", "value must match exactly one branch");
    return issues;
  }
  if (node.type !== undefined) {
    const types = Array.isArray(node.type) ? node.type : [node.type];
    if (!types.some((type) => isType(value, type))) {
      add("type", `expected ${types.join(" or ")}`);
      return issues;
    }
  }
  if (hasOwn(node, "const") && !deepEqual(value, node.const)) add("const", `expected ${JSON.stringify(node.const)}`);
  if (node.enum && !node.enum.some((candidate) => deepEqual(value, candidate))) add("enum", "value is not allowed");
  if (typeof value === "string") {
    if (node.minLength !== undefined && value.length < node.minLength) add("minLength", `minimum length is ${node.minLength}`);
    if (node.maxLength !== undefined && value.length > node.maxLength) add("maxLength", `maximum length is ${node.maxLength}`);
    if (node.pattern && !new RegExp(node.pattern).test(value)) add("pattern", `value does not match ${node.pattern}`);
    if (node.format === "date" && !isCalendarDate(value)) add("format", "invalid date");
    if (node.format === "date-time" && !isDateTime(value)) add("format", "invalid date-time");
    if (node.format === "uri" && !isUri(value)) add("format", "invalid URI");
  }
  if (typeof value === "number" && node.minimum !== undefined && value < node.minimum) add("minimum", `minimum is ${node.minimum}`);
  if (Array.isArray(value)) {
    if (node.minItems !== undefined && value.length < node.minItems) add("minItems", `minimum items is ${node.minItems}`);
    if (node.uniqueItems && new Set(value.map(stableStringify)).size !== value.length) add("uniqueItems", "items must be unique");
    if (node.items) value.forEach((item, index) => issues.push(...validateSchemaNode(item, node.items, root, childPath(path, index))));
  }
  if (isObject(value)) {
    const properties = node.properties ?? {};
    const patterns = Object.entries(node.patternProperties ?? {}).map(([pattern, child]) => [new RegExp(pattern), child]);
    for (const required of node.required ?? []) if (!hasOwn(value, required)) add("required", "required property is missing", childPath(path, required));
    for (const [key, child] of Object.entries(value)) {
      const direct = properties[key];
      const matched = patterns.filter(([pattern]) => pattern.test(key)).map(([, schema]) => schema);
      if (direct) issues.push(...validateSchemaNode(child, direct, root, childPath(path, key)));
      for (const patternSchema of matched) issues.push(...validateSchemaNode(child, patternSchema, root, childPath(path, key)));
      if (!direct && matched.length === 0 && node.additionalProperties === false) add("additionalProperties", "additional property is not allowed", childPath(path, key));
    }
  }
  return issues;
};

const errorCodeForStructure = (path, kind) => {
  if (path === "/manifest_version" || path.startsWith("/compatibility")) return "COMPATIBILITY_INVALID";
  if (path.startsWith("/storage")) return path.endsWith("relative_path") ? "PATH_UNSAFE" : "STORAGE_INVALID";
  if (path.startsWith("/previous_good")) return "PREVIOUS_GOOD_INVALID";
  if (path.startsWith("/rights_policy")) return "RIGHTS_POLICY_INVALID";
  if (path.startsWith("/clocks") || path.includes("_at")) return "CLOCK_INVALID";
  if (path.startsWith("/release_bounds")) return "RELEASE_BOUND_INVALID";
  if (path.includes("relative_path")) return "PATH_UNSAFE";
  if (path.includes("sha256")) return "CHECKSUM_INVALID";
  if (path.includes("source_ids") || path.includes("source_id")) return "SOURCE_INVALID";
  if (kind === "additionalProperties") return "UNKNOWN_FIELD";
  return "MANIFEST_STRUCTURE_INVALID";
};
const addError = (errors, code, path, message) => errors.push({ code, path, message });
const arrayObjects = (value) => Array.isArray(value) ? value.filter(isObject) : [];
const setEquals = (left, right) => deepEqual(sortedUnique(left), sortedUnique(right));
const fieldAllowed = (field, patterns) => patterns.some((pattern) => pattern.endsWith("*") ? field.startsWith(pattern.slice(0, -1)) : field === pattern);
const semanticSha256 = (value) => createHash("sha256").update(stableStringify(value)).digest("hex");
const validateReviewedVersionBaseline = (contract, policy) => {
  const versionKey = `${contract.contract_version}:${policy.policy_version}`;
  const baseline = REVIEWED_VERSION_BASELINES[versionKey];
  if (!baseline || contract.rights_policy_version !== policy.policy_version) return [{ code: "VERSION_TRANSITION_REQUIRED", path: "/contract_version", message: "contract and policy versions must select one reviewed immutable baseline" }];
  if (semanticSha256(contract) !== baseline.content_contract_sha256 || semanticSha256(policy) !== baseline.source_policy_sha256) return [{ code: "VERSION_TRANSITION_REQUIRED", path: "/contract_version", message: "same-version contract or policy drift differs from the reviewed immutable baseline" }];
  return [];
};
const expectedFieldType = (contract, table, field) => {
  const override = contract.field_type_overrides?.[`${table}.${field}`];
  if (override) return override;
  const matches = Object.entries(contract.field_type_groups).filter(([, fields]) => fields.includes(field)).map(([type]) => type);
  if (matches.length > 1) throw new Error(`Field ${field} has multiple type rules: ${matches.join(", ")}`);
  return matches[0] ?? contract.default_field_type;
};
const expectedFields = (contract, table) => contract.tables[table].map((name) => ({ name, type: expectedFieldType(contract, table, name), nullable: contract.nullable_fields[table].includes(name) }));
const expectedOutputLedger = (contract, policy) => {
  const policyById = new Map(policy.sources.map((source) => [source.id, source]));
  const sourceIdsForTable = (table, stack = new Set()) => {
    const direct = contract.source_field_bindings[table]?.source_id;
    if (direct) return [direct];
    if (stack.has(table)) return [];
    const next = new Set(stack).add(table);
    const dependencies = contract.table_derivation_dependencies[table] ?? [];
    if (dependencies.length === 0) return [...contract.required_source_ids];
    return sortedUnique(dependencies.flatMap((input) => sourceIdsForTable(input.split(".")[0], next)));
  };
  const fieldLineage = [];
  const derivations = [];
  for (const [table, fields] of Object.entries(contract.tables)) {
    const binding = contract.source_field_bindings[table];
    const boundFields = Object.keys(binding?.fields ?? {});
    if (binding) {
      const noticeIds = sortedUnique(policyById.get(binding.source_id).required_notice_ids);
      for (const [field, sourceField] of Object.entries(binding.fields)) fieldLineage.push({ table, field, source_id: binding.source_id, source_field: sourceField, transformation_id: "source_normalize_v1", notice_ids: noticeIds, pointer_semantics: "source_value", provenance_required: true });
    }
    for (const field of fields.filter((candidate) => !boundFields.includes(candidate))) {
      const output = `${table}.${field}`;
      let sourceIds = sourceIdsForTable(table);
      let noticeIds = sortedUnique(sourceIds.flatMap((sourceId) => policyById.get(sourceId)?.required_notice_ids ?? []));
      let ruleId = `derive_${table}_${field}_v1`;
      let transformationId = "derived_projection_v1";
      let pointerSemantics = "derived_value";
      let inputFields = contract.derivation_input_overrides[output] ?? (boundFields.length > 0 ? boundFields.map((name) => `${table}.${name}`) : contract.table_derivation_dependencies[table] ?? []);
      if (field === "schema_version") {
        ruleId = "schema_version_constant_v1";
        transformationId = "constant_v1";
        pointerSemantics = "constant";
        inputFields = [];
        sourceIds = [];
        noticeIds = [];
      } else if (field === "rights_policy_version") {
        ruleId = "rights_policy_version_constant_v1";
        transformationId = "constant_v1";
        pointerSemantics = "constant";
        inputFields = [];
        sourceIds = [];
        noticeIds = [];
      } else if (field === "observation_id") {
        ruleId = "stable_observation_id_v1";
        transformationId = "sha256_identity_v1";
        pointerSemantics = "observation_identity";
        inputFields = boundFields.map((name) => `${table}.${name}`);
      } else if (field === "provenance_id") {
        ruleId = "provenance_pointer_v1";
        transformationId = "foreign_key_pointer_v1";
        pointerSemantics = "provenance_pointer";
        inputFields = fields.includes("observation_id") ? [`${table}.observation_id`] : inputFields;
      } else if (field.endsWith("observation_id") || field === "selected_observation_id") {
        ruleId = "observation_pointer_v1";
        transformationId = "foreign_key_pointer_v1";
        pointerSemantics = "observation_pointer";
      } else if (field.endsWith("derivation_id") || field === "derivation_id") {
        ruleId = "derivation_pointer_v1";
        transformationId = "foreign_key_pointer_v1";
        pointerSemantics = "derivation_pointer";
      } else if (field === "source_id") {
        ruleId = "source_identity_constant_v1";
        transformationId = "source_identity_v1";
        pointerSemantics = "source_identity";
        inputFields = [];
      } else if (table === "affected_software" && ["configuration_id", "node_id", "parent_node_id"].includes(field)) {
        ruleId = "nvd_source_path_identity_v1";
        transformationId = "source_path_index_v1";
      }
      derivations.push({ output_table: table, output_field: field, rule_id: ruleId, rule_version: 1, transformation_id: transformationId, input_fields: sortedUnique(inputFields), source_ids: sourceIds, notice_ids: noticeIds, pointer_semantics: pointerSemantics, provenance_required: true });
    }
  }
  return { fieldLineage, derivations };
};

const validateSourcePolicy = (policy, schema, contract) => {
  const errors = validateSchemaNode(policy, schema, schema).map((issue) => ({ code: "SOURCE_POLICY_STRUCTURE_INVALID", path: issue.path || "/", message: issue.message }));
  if (!isObject(policy)) return errors;
  const sources = arrayObjects(policy.sources);
  const byId = new Map(sources.map((source) => [source.id, source]));
  for (const duplicate of duplicates(sources.map((source) => source.id))) addError(errors, "SOURCE_DUPLICATE", "/sources", `duplicate source ${duplicate}`);
  if (policy.policy_version !== contract.rights_policy_version) addError(errors, "RIGHTS_POLICY_VERSION_MISMATCH", "/policy_version", "policy and data contract versions differ");
  const registered = [...contract.required_source_ids, ...contract.forbidden_source_ids];
  if (!setEquals(sources.map((source) => source.id), registered)) addError(errors, "SOURCE_REGISTRY_MISMATCH", "/sources", "registry must contain exactly the v1 allowed and forbidden sources");
  for (const sourceId of contract.required_source_ids) {
    const source = byId.get(sourceId);
    const requirement = contract.source_requirements[sourceId];
    if (!source || source.decision !== "allow" || source.enabled !== true || !source.allowed_use_modes?.includes(policy.use_mode)) addError(errors, "SOURCE_NOT_ENABLED", "/sources", `${sourceId} is not enabled for public dataset republication`);
    if (source?.raw_publication !== false || source?.field_lineage_required !== true || source?.record_path_required !== true || source?.record_sha256_required !== true) addError(errors, "SOURCE_GATE_INCOMPLETE", "/sources", `${sourceId} lacks mandatory normalized-field lineage controls`);
    if (!Array.isArray(source?.allowed_fields) || source.allowed_fields.length === 0) addError(errors, "SOURCE_FIELDS_MISSING", "/sources", `${sourceId} has no field allow-list`);
    if (!Array.isArray(source?.required_notice_ids) || source.required_notice_ids.length === 0) addError(errors, "SOURCE_NOTICE_MISSING", "/sources", `${sourceId} has no required notice`);
    const sourceFingerprint = source ? createHash("sha256").update(stableStringify(source)).digest("hex") : null;
    if (!requirement || source?.source_locator !== requirement.source_locator || sourceFingerprint !== requirement.policy_source_sha256) addError(errors, "SOURCE_POLICY_WIDENED", "/sources", `${sourceId} differs from its reviewed source, field, artifact, notice, mode, or retention rule`);
    if (requirement?.watermark_kind === "git_commit" && source?.repository !== requirement.source_locator) addError(errors, "SOURCE_POLICY_WIDENED", "/sources", `${sourceId} must pin its reviewed Git repository`);
    if ((source?.allowed_fields ?? []).some((field) => /(?:^|[._])raw(?:[._]|$)|source_raw|source_payload/i.test(field))) addError(errors, "SOURCE_POLICY_WIDENED", "/sources", `${sourceId} may not allow raw/source payload fields`);
  }
  for (const sourceId of contract.forbidden_source_ids) {
    const source = byId.get(sourceId);
    if (!source || source.enabled !== false || source.allowed_use_modes?.length !== 0 || source.allowed_fields?.length !== 0 || source.raw_publication !== false) addError(errors, "FORBIDDEN_SOURCE_ENABLED", "/sources", `${sourceId} must fail closed`);
  }
  const cve = byId.get("patch8_cvelist_v5");
  const cveFields = ["dataVersion", "cveMetadata.cveId", "cveMetadata.state", "cveMetadata.datePublished", "cveMetadata.dateUpdated", "cveMetadata.assignerOrgId", "cveMetadata.assignerShortName", "containers.cna.providerMetadata.orgId", "containers.cna.providerMetadata.shortName", "containers.cna.providerMetadata.dateUpdated", "containers.cna.descriptions[].lang", "containers.cna.descriptions[].value"];
  if (!setEquals(cve?.allowed_fields ?? [], cveFields) || cve?.repository !== "https://github.com/CVEProject/cvelistV5" || cve?.immutable_revision_required !== true || !cve?.official_terms_urls?.includes("https://www.cve.org/Legal/TermsOfUse") || !cve?.official_terms_urls?.includes("https://www.cve.org/Downloads")) addError(errors, "CVELIST_RULE_INVALID", "/sources", "cvelistV5 rule must pin official terms, repository, immutable revision, and exact v1 fields");
  const nvdRequired = ["cve.configurations[].operator", "cve.configurations[].negate", "cve.configurations[].nodes[].operator", "cve.configurations[].nodes[].negate", "cve.configurations[].nodes[].cpeMatch[].vulnerable", "cve.configurations[].nodes[].cpeMatch[].criteria", "cve.configurations[].nodes[].cpeMatch[].matchCriteriaId", "cve.configurations[].nodes[].cpeMatch[].versionStartIncluding", "cve.configurations[].nodes[].cpeMatch[].versionStartExcluding", "cve.configurations[].nodes[].cpeMatch[].versionEndIncluding", "cve.configurations[].nodes[].cpeMatch[].versionEndExcluding"];
  const nvdDerivedOnly = ["configuration_id", "node_id", "parent_node_id"];
  if (!nvdRequired.every((field) => byId.get("patch8_nvd")?.allowed_fields?.includes(field)) || nvdDerivedOnly.some((field) => byId.get("patch8_nvd")?.allowed_fields?.some((allowed) => allowed.endsWith(field)))) addError(errors, "NVD_STRUCTURE_RULE_INCOMPLETE", "/sources", "NVD raw Boolean-tree/version paths must be exact and Link42 path identities must remain derived");
  if (errors.length === 0) errors.push(...validateReviewedVersionBaseline(contract, policy));
  return errors;
};

const assertContentContract = (contract, policy) => {
  const failures = [];
  const tableIds = Object.keys(contract.tables);
  const policyById = new Map(policy.sources.map((source) => [source.id, source]));
  if (!setEquals(Object.keys(contract.nullable_fields), tableIds)) failures.push("nullable_fields must cover exactly every table");
  if (!setEquals(Object.keys(contract.table_keys), tableIds)) failures.push("table_keys must cover exactly every table");
  if (!setEquals(Object.keys(contract.source_requirements), contract.required_source_ids)) failures.push("source_requirements must cover exactly every enabled source");
  if (!setEquals(Object.keys(contract.capability_source_dependencies), Object.keys(contract.required_capabilities))) failures.push("capability dependencies must cover exactly every capability");
  const allFields = new Set(tableIds.flatMap((table) => contract.tables[table]));
  for (const [table, fields] of Object.entries(contract.tables)) {
    if (duplicates(fields).length) failures.push(`${table} has duplicate fields`);
    if (!contract.nullable_fields[table].every((field) => fields.includes(field))) failures.push(`${table} has unknown nullable fields`);
    const keys = contract.table_keys[table];
    if (![...keys.primary_key, ...keys.sort_keys].every((field) => fields.includes(field))) failures.push(`${table} has unknown primary/sort keys`);
    for (const field of fields) expectedFieldType(contract, table, field);
  }
  for (const fields of Object.values(contract.field_type_groups)) for (const field of fields) if (!allFields.has(field)) failures.push(`type rule references unknown field ${field}`);
  for (const [output, type] of Object.entries(contract.field_type_overrides)) {
    const [table, field] = output.split(".");
    if (!contract.tables[table]?.includes(field) || typeof type !== "string") failures.push(`invalid type override ${output}`);
  }
  for (const [table, binding] of Object.entries(contract.source_field_bindings)) {
    const source = policyById.get(binding.source_id);
    if (!contract.tables[table] || !source) failures.push(`invalid source binding ${table}`);
    for (const [field, sourceField] of Object.entries(binding.fields)) {
      if (!contract.tables[table]?.includes(field) || !fieldAllowed(sourceField, source?.allowed_fields ?? [])) failures.push(`unauthorized source binding ${table}.${field}`);
    }
  }
  const validateInput = (input) => {
    const [table, ...field] = input.split(".");
    return contract.tables[table]?.includes(field.join("."));
  };
  for (const [output, inputs] of Object.entries(contract.derivation_input_overrides)) {
    const [table, field] = output.split(".");
    if (!contract.tables[table]?.includes(field) || !inputs.every(validateInput)) failures.push(`invalid derivation override ${output}`);
  }
  for (const [table, inputs] of Object.entries(contract.table_derivation_dependencies)) if (!contract.tables[table] || !inputs.every(validateInput)) failures.push(`invalid table derivation dependencies ${table}`);
  for (const [capability, sources] of Object.entries(contract.capability_source_dependencies)) if (!hasOwn(contract.required_capabilities, capability) || !sources.every((source) => contract.required_source_ids.includes(source))) failures.push(`invalid capability dependency ${capability}`);
  if (failures.length) throw new Error(`Patch8 content contract sentinel failed:\n- ${failures.join("\n- ")}`);
};

const validateManifest = (manifest, reader, schema, policy, contract, policySha) => {
  const errors = validateSchemaNode(manifest, schema, schema).map((issue) => ({ code: errorCodeForStructure(issue.path || "/", issue.keyword), path: issue.path || "/", message: issue.message }));
  if (!isObject(manifest)) return errors;
  const add = (code, path, message) => addError(errors, code, path, message);
  const storage = manifest.storage ?? {};
  const compatibility = manifest.compatibility ?? {};
  const bounds = manifest.release_bounds ?? {};
  const schemas = arrayObjects(manifest.table_schemas);
  const routes = arrayObjects(manifest.routing);
  const artifacts = arrayObjects(manifest.artifacts);
  const snapshots = arrayObjects(manifest.source_snapshots);
  const lineages = arrayObjects(manifest.field_lineage);
  const derivations = arrayObjects(manifest.derivations);
  const policySources = new Map(arrayObjects(policy.sources).map((source) => [source.id, source]));
  const schemasById = new Map(schemas.map((table) => [table.id, table]));
  const snapshotsById = new Map(snapshots.map((snapshot) => [snapshot.source_id, snapshot]));

  if (reader.manifest_version < compatibility.min_reader_manifest_version || reader.manifest_version > compatibility.max_reader_manifest_version || reader.schema_version < compatibility.min_schema_version || reader.schema_version > compatibility.max_schema_version) add("COMPATIBILITY_INVALID", "/compatibility", "reader is outside manifest/schema compatibility bounds");
  if (compatibility.min_reader_manifest_version > compatibility.max_reader_manifest_version || compatibility.min_schema_version > compatibility.max_schema_version || compatibility.rights_policy_version !== policy.policy_version) add("COMPATIBILITY_INVALID", "/compatibility", "compatibility ranges or policy version are invalid");
  const expectedBase = `https://huggingface.co/datasets/link42-au/patch/resolve/${storage.immutable_data_revision}/`;
  if (storage.base_url !== expectedBase) add("MIXED_REVISION", "/storage/base_url", "base URL must pin the declared immutable data revision");
  if (manifest.rights_policy?.sha256 !== policySha || manifest.rights_policy?.version !== policy.policy_version) add("RIGHTS_POLICY_INVALID", "/rights_policy", "manifest must bind the exact checked source policy");
  const previous = manifest.previous_good;
  if (isObject(previous)) {
    const expectedPreviousUrl = `https://huggingface.co/datasets/link42-au/patch/resolve/${previous.manifest_revision}/dataset-manifest.json`;
    if (previous.release_id === manifest.release_id || previous.data_revision === storage.immutable_data_revision || previous.manifest_url !== expectedPreviousUrl) add("PREVIOUS_GOOD_INVALID", "/previous_good", "previous-good must be distinct and pin its manifest revision");
  }
  const clockKeys = ["latest_source_modified_at", "latest_source_checked_at", "dataset_built_at", "manifest_published_at", "stale_at"];
  const clockTimes = clockKeys.map((key) => Date.parse(manifest.clocks?.[key]));
  if (clockTimes.some(Number.isNaN) || clockTimes.some((time, index) => index > 0 && time < clockTimes[index - 1])) add("CLOCK_INVALID", "/clocks", "source-modified, checked, built, published, and stale clocks must be ordered");
  if (bounds.observed_repository_revisions > bounds.max_repository_revisions || bounds.observed_retained_bytes > bounds.max_retained_bytes) add("REPOSITORY_GROWTH_EXCEEDED", "/release_bounds", "repository revision or retained-byte ceiling exceeded");
  for (const [values, code, path] of [[schemas.map((item) => item.id), "TABLE_DUPLICATE", "/table_schemas"], [routes.map((item) => item.schema_id), "ROUTING_DUPLICATE", "/routing"], [artifacts.map((item) => item.id), "ARTIFACT_DUPLICATE", "/artifacts"], [artifacts.map((item) => item.relative_path), "PATH_DUPLICATE", "/artifacts"], [snapshots.map((item) => item.source_id), "SOURCE_DUPLICATE", "/source_snapshots"], [lineages.map((item) => `${item.table}.${item.field}`), "FIELD_LINEAGE_DUPLICATE", "/field_lineage"], [derivations.map((item) => `${item.output_table}.${item.output_field}`), "DERIVATION_DUPLICATE", "/derivations"]]) {
    for (const duplicate of duplicates(values)) add(code, path, `duplicate ${duplicate}`);
  }
  const expectedLedger = expectedOutputLedger(contract, policy);
  const sortLineage = (entries) => [...entries].sort((left, right) => `${left.table}.${left.field}`.localeCompare(`${right.table}.${right.field}`));
  const sortDerivations = (entries) => [...entries].sort((left, right) => `${left.output_table}.${left.output_field}`.localeCompare(`${right.output_table}.${right.output_field}`));
  if (!deepEqual(sortLineage(lineages), sortLineage(expectedLedger.fieldLineage)) || !deepEqual(sortDerivations(derivations), sortDerivations(expectedLedger.derivations))) add("OUTPUT_LEDGER_INVALID", "/field_lineage", "field lineage and derivations must exactly match the reviewed source/input/rule/notice/pointer ledger");
  const requiredTableIds = Object.keys(contract.tables);
  if (!setEquals(schemas.map((table) => table.id), requiredTableIds)) add("TABLE_COVERAGE_INVALID", "/table_schemas", "manifest must declare exactly every v1 table/read model");
  const routesBySchema = new Map(routes.map((route) => [route.schema_id, route]));
  for (const table of schemas) {
    const fields = arrayObjects(table.fields);
    const fieldNames = fields.map((field) => field.name);
    if (!deepEqual(fields, expectedFields(contract, table.id)) || !deepEqual(table.primary_key, contract.table_keys[table.id]?.primary_key) || !deepEqual(table.sort_keys, contract.table_keys[table.id]?.sort_keys)) add("TABLE_SCHEMA_INVALID", "/table_schemas", `${table.id} fields, types, nullability, primary key, or sort keys differ from the authoritative v1 contract`);
    if (duplicates(fieldNames).length > 0 || !table.primary_key?.every((key) => fieldNames.includes(key)) || !table.sort_keys?.every((key) => fieldNames.includes(key))) add("TABLE_SCHEMA_INVALID", "/table_schemas", `${table.id} has invalid fields or keys`);
    const expectedFingerprint = createHash("sha256").update(stableStringify({ id: table.id, version: table.version, primary_key: table.primary_key, sort_keys: table.sort_keys, fields: table.fields })).digest("hex");
    if (table.schema_sha256 !== expectedFingerprint) add("TABLE_SCHEMA_FINGERPRINT_INVALID", "/table_schemas", `${table.id} fingerprint does not bind its ordered fields and keys`);
    const route = routesBySchema.get(table.id);
    if (!route || route.maximum_candidate_artifacts > bounds.max_candidate_artifacts_per_query || !arrayObjects(route.dimensions).every((dimension) => fieldNames.includes(dimension.source_field))) add("ROUTING_INVALID", "/routing", `${table.id} lacks a bounded field-valid route`);
    if (!artifacts.some((artifact) => artifact.schema_id === table.id)) add("ARTIFACT_COVERAGE_INVALID", "/artifacts", `${table.id} has no artifact`);
  }
  const forbiddenTokens = contract.forbidden_tokens.map((token) => token.toLowerCase());
  for (const artifact of artifacts) {
    const table = schemasById.get(artifact.schema_id);
    if (!table || artifact.schema_version !== table.version) add("ARTIFACT_SCHEMA_INVALID", "/artifacts", `${artifact.id} references an unknown/mismatched schema`);
    if (artifact.data_revision !== storage.immutable_data_revision) add("MIXED_REVISION", "/artifacts", `${artifact.id} uses a different data revision`);
    if (artifact.byte_size > bounds.max_artifact_bytes || artifact.row_count > bounds.max_rows_per_artifact) add("ARTIFACT_BOUND_EXCEEDED", "/artifacts", `${artifact.id} exceeds byte or row bounds`);
    if (typeof artifact.key_min === typeof artifact.key_max && artifact.key_min !== null && artifact.key_min > artifact.key_max) add("PARTITION_BOUND_INVALID", "/artifacts", `${artifact.id} has reversed key bounds`);
    const route = routesBySchema.get(artifact.schema_id);
    const expectedKeys = arrayObjects(route?.dimensions).map((dimension) => dimension.partition_key);
    if (!setEquals(Object.keys(artifact.partition_values ?? {}), expectedKeys)) add("PARTITION_BOUND_INVALID", "/artifacts", `${artifact.id} partition coordinates do not match routing`);
    if (forbiddenTokens.some((token) => artifact.relative_path?.toLowerCase().includes(token))) add("BLOCKED_ARTIFACT", "/artifacts", `${artifact.id} path claims blocked/raw data`);
    for (const sourceId of artifact.source_ids ?? []) {
      const source = policySources.get(sourceId);
      if (!source || source.enabled !== true || source.decision !== "allow" || !snapshotsById.has(sourceId)) add("SOURCE_INVALID", "/artifacts", `${artifact.id} references an unknown, disabled, or unsnapshotted source`);
    }
  }
  if (!setEquals(snapshots.map((snapshot) => snapshot.source_id), contract.required_source_ids)) add("SOURCE_COVERAGE_INVALID", "/source_snapshots", "source snapshots must cover exactly the complete v1 source set");
  for (const snapshot of snapshots) {
    const source = policySources.get(snapshot.source_id);
    const requirement = contract.source_requirements[snapshot.source_id];
    if (!source || source.enabled !== true || source.decision !== "allow") {
      add("SOURCE_INVALID", "/source_snapshots", `${snapshot.source_id} is not enabled`);
      continue;
    }
    if (source.immutable_revision_required && !REVISION_PATTERN.test(snapshot.immutable_revision ?? "")) add("SOURCE_REVISION_UNPINNED", "/source_snapshots", `${snapshot.source_id} requires an immutable Git revision`);
    if (!requirement || snapshot.endpoint_or_repository !== requirement.source_locator || snapshot.watermark?.kind !== requirement.watermark_kind) add("SOURCE_IDENTITY_INVALID", "/source_snapshots", `${snapshot.source_id} locator or watermark kind differs from its reviewed source contract`);
    if (!setEquals(snapshot.notice_ids ?? [], source.required_notice_ids ?? [])) add("SOURCE_NOTICE_INVALID", "/source_snapshots", `${snapshot.source_id} does not carry its exact notices`);
    const times = [snapshot.source_modified_at, snapshot.checked_at, snapshot.source_retrieved_at, snapshot.source_observed_at].map(Date.parse);
    if (times.some(Number.isNaN) || times.some((time, index) => index > 0 && time < times[index - 1]) || times[3] > Date.parse(manifest.clocks?.dataset_built_at)) add("CLOCK_INVALID", "/source_snapshots", `${snapshot.source_id} snapshot clocks are invalid`);
    const watermark = snapshot.watermark ?? {};
    if (watermark.contiguous !== true || snapshot.last_successful_watermark !== watermark.cursor) add("WATERMARK_GAP", "/source_snapshots", `${snapshot.source_id} watermark is not contiguous and bound to the successful cursor`);
    if (requirement?.watermark_kind === "git_commit" && (watermark.kind !== "git_commit" || watermark.cursor !== snapshot.immutable_revision || !REVISION_PATTERN.test(snapshot.immutable_revision ?? ""))) add("SOURCE_REVISION_UNPINNED", "/source_snapshots", `${snapshot.source_id} Git cursor does not match its immutable revision`);
    if (watermark.kind === "api_window" && (snapshot.source_id !== "patch8_nvd" || watermark.previous_end !== watermark.window_start || Date.parse(watermark.window_end) > Date.parse(snapshot.checked_at))) add("WATERMARK_GAP", "/source_snapshots", `${snapshot.source_id} API window is not contiguous`);
  }
  const latestSnapshotModifiedAt = snapshots.map((snapshot) => snapshot.source_modified_at).sort().at(-1);
  const latestSnapshotCheckedAt = snapshots.map((snapshot) => snapshot.checked_at).sort().at(-1);
  if (manifest.clocks?.latest_source_modified_at !== latestSnapshotModifiedAt || manifest.clocks?.latest_source_checked_at !== latestSnapshotCheckedAt) add("CLOCK_INVALID", "/clocks", "manifest source clocks must equal the latest declared source snapshot clocks");
  const lineageByOutput = new Map(lineages.map((entry) => [`${entry.table}.${entry.field}`, entry]));
  const derivationByOutput = new Map(derivations.map((entry) => [`${entry.output_table}.${entry.output_field}`, entry]));
  for (const table of schemas) {
    for (const field of arrayObjects(table.fields)) {
      const key = `${table.id}.${field.name}`;
      const lineage = lineageByOutput.get(key);
      const derivation = derivationByOutput.get(key);
      if (Boolean(lineage) === Boolean(derivation)) add("FIELD_PROVENANCE_INVALID", "/field_lineage", `${key} must have exactly one source lineage or derivation`);
      if (forbiddenTokens.some((token) => key.toLowerCase().includes(token))) add("BLOCKED_FIELD", "/table_schemas", `${key} is blocked by v1`);
      if (lineage) {
        const source = policySources.get(lineage.source_id);
        if (!source || source.enabled !== true || !fieldAllowed(lineage.source_field, source.allowed_fields ?? [])) add("FIELD_NOT_ALLOWED", "/field_lineage", `${key} is not authorized by ${lineage.source_id}`);
      }
    }
  }
  for (const lineage of lineages) if (!schemasById.get(lineage.table)?.fields?.some((field) => field.name === lineage.field)) add("FIELD_PROVENANCE_INVALID", "/field_lineage", `lineage targets unknown ${lineage.table}.${lineage.field}`);
  for (const derivation of derivations) {
    if (!schemasById.get(derivation.output_table)?.fields?.some((field) => field.name === derivation.output_field) || !derivation.input_fields.every((input) => { const [tableId, ...fieldParts] = input.split("."); return schemasById.get(tableId)?.fields?.some((field) => field.name === fieldParts.join(".")); }) || !derivation.source_ids.every((sourceId) => contract.required_source_ids.includes(sourceId)) || !setEquals(derivation.notice_ids, derivation.source_ids.flatMap((sourceId) => policySources.get(sourceId)?.required_notice_ids ?? []))) add("DERIVATION_INVALID", "/derivations", `${derivation.output_table}.${derivation.output_field} has unknown or unauthorized inputs, sources, or notices`);
  }
  const sourceCoverage = arrayObjects(manifest.coverage?.sources);
  for (const duplicate of duplicates(sourceCoverage.map((entry) => entry.source_id))) add("SOURCE_COVERAGE_DUPLICATE", "/coverage/sources", `duplicate source coverage ${duplicate}`);
  if (!setEquals(sourceCoverage.map((entry) => entry.source_id), contract.required_source_ids)) add("SOURCE_COVERAGE_INVALID", "/coverage/sources", "coverage must name every and only v1 source");
  const sourceCoverageById = new Map(sourceCoverage.map((entry) => [entry.source_id, entry]));
  for (const entry of sourceCoverage) {
    const freshnessMs = contract.freshness_hours[entry.source_id] * 60 * 60 * 1000;
    const snapshot = snapshotsById.get(entry.source_id);
    if (!snapshot || entry.checked_at !== snapshot.checked_at || Date.parse(entry.stale_at) - Date.parse(entry.checked_at) !== freshnessMs) add("FRESHNESS_BOUND_INVALID", "/coverage/sources", `${entry.source_id} check/stale clocks differ from its snapshot or v1 threshold`);
    const expectedTimeState = Date.parse(manifest.clocks?.manifest_published_at) >= Date.parse(entry.stale_at) ? "stale" : "current";
    if (entry.state !== "unavailable" && entry.state !== expectedTimeState) add("SOURCE_STATE_INVALID", "/coverage/sources", `${entry.source_id} state is inconsistent with publication and stale clocks`);
  }
  const earliestSourceStaleAt = sourceCoverage.map((entry) => entry.stale_at).sort().at(0);
  if (manifest.clocks?.stale_at !== earliestSourceStaleAt) add("CLOCK_INVALID", "/clocks/stale_at", "manifest stale clock must equal the earliest source freshness boundary");
  const capabilities = arrayObjects(manifest.coverage?.capabilities);
  for (const duplicate of duplicates(capabilities.map((entry) => entry.capability_id))) add("CAPABILITY_COVERAGE_DUPLICATE", "/coverage/capabilities", `duplicate capability coverage ${duplicate}`);
  if (!setEquals(capabilities.map((entry) => entry.capability_id), Object.keys(contract.required_capabilities))) add("CAPABILITY_COVERAGE_INVALID", "/coverage/capabilities", "capability coverage is incomplete or unknown");
  for (const capability of capabilities) {
    const nominalState = contract.required_capabilities[capability.capability_id];
    const requiredSources = contract.capability_source_dependencies[capability.capability_id] ?? [];
    const sourceStates = requiredSources.map((sourceId) => sourceCoverageById.get(sourceId)?.state);
    const expectedState = ["unavailable", "unsupported"].includes(nominalState) ? nominalState : sourceStates.includes("unavailable") ? "unavailable" : sourceStates.includes("stale") ? "stale" : nominalState;
    if (capability.state !== expectedState || !deepEqual(capability.source_ids, requiredSources) || capability.as_at !== manifest.clocks?.dataset_built_at) add("CAPABILITY_STATE_INVALID", "/coverage/capabilities", `${capability.capability_id} state, dependencies, or as-at clock differs from v1 contract`);
    const numerator = capability.coverage_numerator;
    const denominator = capability.coverage_denominator;
    if (["unavailable", "unsupported"].includes(capability.state) && (numerator !== null || denominator !== null)) add("CAPABILITY_FALSE_ZERO", "/coverage/capabilities", `${capability.capability_id} unavailable state must not claim zero coverage`);
    if (["supported", "partial"].includes(capability.state) && (!Number.isInteger(numerator) || !Number.isInteger(denominator) || denominator <= 0 || numerator > denominator || (capability.state === "supported" && numerator !== denominator) || (capability.state === "partial" && numerator >= denominator))) add("CAPABILITY_COVERAGE_INVALID", "/coverage/capabilities", `${capability.capability_id} numerator/denominator contradict its state`);
    for (const sourceId of capability.source_ids) if (!contract.required_source_ids.includes(sourceId)) add("SOURCE_INVALID", "/coverage/capabilities", `${capability.capability_id} references a forbidden source`);
  }
  if (errors.length === 0) errors.push(...validateReviewedVersionBaseline(contract, policy));
  return errors;
};

const clone = (value) => JSON.parse(JSON.stringify(value));
const decodePointer = (pointer) => pointer.split("/").slice(1).map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"));
const applyMutation = (document, mutation) => {
  if (mutation.operation === "append") {
    const target = decodePointer(mutation.path).reduce((node, part) => node[Array.isArray(node) ? Number(part) : part], document);
    target.push(clone(mutation.value));
    return;
  }
  if (mutation.operation === "copy") {
    const source = decodePointer(mutation.from).reduce((node, part) => node[Array.isArray(node) ? Number(part) : part], document);
    const target = decodePointer(mutation.path).reduce((node, part) => node[Array.isArray(node) ? Number(part) : part], document);
    target.push(clone(source));
    return;
  }
  if (mutation.operation === "set_matching" || mutation.operation === "delete_matching") {
    const target = decodePointer(mutation.path).reduce((node, part) => node[Array.isArray(node) ? Number(part) : part], document);
    const index = target.findIndex((entry) => Object.entries(mutation.match).every(([key, value]) => deepEqual(entry[key], value)));
    if (index < 0) throw new Error(`Mutation did not find match at ${mutation.path}`);
    if (mutation.operation === "delete_matching") target.splice(index, 1);
    else target[index][mutation.field] = clone(mutation.value);
    return;
  }
  const parts = decodePointer(mutation.path);
  const key = parts.pop();
  const parent = parts.reduce((node, part) => node[Array.isArray(node) ? Number(part) : part], document);
  if (mutation.operation === "delete") {
    if (Array.isArray(parent)) parent.splice(Number(key), 1);
    else delete parent[key];
  } else {
    parent[Array.isArray(parent) ? Number(key) : key] = mutation.value;
  }
};

const createFixtureManifest = (contract, policy, policySha) => {
  const revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const tableIds = Object.keys(contract.tables);
  const sourceForTable = (table) => {
    if (table.startsWith("ghsa") || table.includes("package")) return ["patch8_github_advisory_database", "id"];
    if (table.startsWith("cwe")) return ["patch8_mitre_cwe", "cwe_id"];
    if (table.startsWith("kev")) return ["patch8_cisa_kev", "vulnerabilities.*"];
    if (table.startsWith("ssvc")) return ["patch8_cisa_vulnrichment", "containers.adp[provider=CISA-ADP].metrics"];
    if (["cvss_observations", "weakness_observations", "references", "affected_software", "software_product_vulnerabilities"].includes(table)) return ["patch8_nvd", "cve.id"];
    return ["patch8_cvelist_v5", "cveMetadata.cveId"];
  };
  const schemas = tableIds.map((id) => ({ id, version: 1, schema_sha256: "", primary_key: contract.table_keys[id].primary_key, sort_keys: contract.table_keys[id].sort_keys, fields: expectedFields(contract, id) }));
  for (const table of schemas) table.schema_sha256 = createHash("sha256").update(stableStringify({ id: table.id, version: table.version, primary_key: table.primary_key, sort_keys: table.sort_keys, fields: table.fields })).digest("hex");
  const routing = tableIds.map((schema_id) => ({ schema_id, maximum_candidate_artifacts: 1, dimensions: [{ partition_key: "bucket", source_field: contract.tables[schema_id][0], transform: "constant", parameter: "current" }] }));
  const artifacts = tableIds.map((schema_id, index) => ({ id: `${schema_id}.current`, kind: "parquet", schema_id, schema_version: 1, data_revision: revision, relative_path: `tables/${schema_id}/bucket=current/part-00000.parquet`, media_type: "application/vnd.apache.parquet", byte_size: 1024 + index, sha256: createHash("sha256").update(`artifact:${schema_id}`).digest("hex"), row_count: 1, partition_values: { bucket: "current" }, key_min: "record-1", key_max: "record-1", source_ids: [sourceForTable(schema_id)[0]] }));
  const sourceConfig = {
    patch8_cvelist_v5: ["https://github.com/CVEProject/cvelistV5", "git_commit", revision, "cves/2026/0xxx/CVE-2026-0001.json", ["notice.cve_program"]],
    patch8_nvd: ["https://services.nvd.nist.gov/rest/json/cves/2.0", "api_window", null, "cves/CVE-2026-0001", ["notice.nvd"]],
    patch8_cisa_kev: ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "catalogue_version", null, "vulnerabilities/CVE-2026-0001", ["notice.cisa_kev"]],
    patch8_github_advisory_database: ["https://github.com/github/advisory-database", "git_commit", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "advisories/github-reviewed/2026/01/GHSA-2345-6789-cfgh/GHSA-2345-6789-cfgh.json", ["notice.github_advisory_database"]],
    patch8_cisa_vulnrichment: ["https://github.com/cisagov/vulnrichment", "git_commit", "cccccccccccccccccccccccccccccccccccccccc", "2026/0xxx/CVE-2026-0001.json", ["notice.cisa_vulnrichment", "notice.cve_program"]],
    patch8_mitre_cwe: ["https://cwe.mitre.org/data/xml/cwec_latest.xml.zip", "archive_version", "dddddddddddddddddddddddddddddddddddddddd", "cwec_v4.19.xml.zip", ["notice.mitre_cwe"]],
  };
  const source_snapshots = contract.required_source_ids.map((source_id) => {
    const [endpoint_or_repository, kind, immutable_revision, record_path, notice_ids] = sourceConfig[source_id];
    const cursor = kind === "git_commit" ? immutable_revision : kind === "api_window" ? "2026-08-29T00:00:00Z" : `${source_id}-2026-08-29`;
    return { source_id, endpoint_or_repository, immutable_revision, record_path, input_sha256: createHash("sha256").update(source_id).digest("hex"), input_bytes: 2048, checked_at: "2026-08-29T01:00:00Z", source_modified_at: "2026-08-29T00:00:00Z", source_retrieved_at: "2026-08-29T01:05:00Z", source_observed_at: "2026-08-29T01:10:00Z", last_successful_watermark: cursor, watermark: kind === "api_window" ? { kind, cursor, contiguous: true, previous_end: "2026-08-28T00:00:00Z", window_start: "2026-08-28T00:00:00Z", window_end: "2026-08-29T00:00:00Z" } : { kind, cursor, contiguous: true }, notice_ids };
  });
  const { fieldLineage: field_lineage, derivations } = expectedOutputLedger(contract, policy);
  const capabilities = Object.entries(contract.required_capabilities).map(([capability_id, state]) => ({ capability_id, state, source_ids: contract.capability_source_dependencies[capability_id], coverage_numerator: ["unavailable", "unsupported"].includes(state) ? null : 1, coverage_denominator: ["unavailable", "unsupported"].includes(state) ? null : state === "partial" ? 2 : 1, as_at: "2026-08-29T01:20:00Z" }));
  return { manifest_version: 1, dataset: "patch8", release_id: "2026-08-29.1", storage: { provider: "huggingface", repository: "link42-au/patch", immutable_data_revision: revision, base_url: `https://huggingface.co/datasets/link42-au/patch/resolve/${revision}/` }, compatibility: { min_reader_manifest_version: 1, max_reader_manifest_version: 1, min_schema_version: 1, max_schema_version: 1, rights_policy_version: contract.rights_policy_version }, rights_policy: { id: "patch8-public-dataset", version: contract.rights_policy_version, schema_version: 1, path: "docs/licensing/source-policy.json", sha256: policySha, use_mode: "public_dataset_republication" }, previous_good: { release_id: "2026-08-28.1", manifest_revision: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", data_revision: "ffffffffffffffffffffffffffffffffffffffff", manifest_url: "https://huggingface.co/datasets/link42-au/patch/resolve/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/dataset-manifest.json", manifest_sha256: "1111111111111111111111111111111111111111111111111111111111111111" }, clocks: { latest_source_checked_at: "2026-08-29T01:00:00Z", latest_source_modified_at: "2026-08-29T00:00:00Z", dataset_built_at: "2026-08-29T01:20:00Z", manifest_published_at: "2026-08-29T01:30:00Z", stale_at: "2026-08-30T07:00:00Z" }, release_bounds: { max_artifact_bytes: 10485760, max_rows_per_artifact: 100000, max_candidate_artifacts_per_query: 8, max_repository_revisions: 64, max_retained_bytes: 10737418240, observed_repository_revisions: 2, observed_retained_bytes: 1048576 }, table_schemas: schemas, routing, artifacts, source_snapshots, field_lineage, derivations, coverage: { sources: contract.required_source_ids.map((source_id) => ({ source_id, state: "current", checked_at: "2026-08-29T01:00:00Z", stale_at: source_id === "patch8_mitre_cwe" ? "2026-09-29T01:00:00Z" : "2026-08-30T07:00:00Z" })), capabilities } };
};

const assertClosedObjects = (schema, name) => {
  const failures = [];
  const visit = (node, path = "#") => {
    if (Array.isArray(node)) return node.forEach((child, index) => visit(child, `${path}/${index}`));
    if (!isObject(node)) return;
    if (node.type === "object" && node.additionalProperties !== false) failures.push(path);
    for (const [key, child] of Object.entries(node)) visit(child, `${path}/${pointerPart(key)}`);
  };
  visit(schema);
  if (failures.length) throw new Error(`${name} has open object schemas:\n- ${failures.join("\n- ")}`);
};

const main = async () => {
  const [manifestSchemaText, policySchemaText, contractText, policyText, fixturesText, policyFixturesText] = await Promise.all([MANIFEST_SCHEMA_URL, POLICY_SCHEMA_URL, CONTENT_CONTRACT_URL, SOURCE_POLICY_URL, FIXTURES_URL, POLICY_FIXTURES_URL].map((url) => readFile(url, "utf8")));
  const manifestSchema = JSON.parse(manifestSchemaText);
  const policySchema = JSON.parse(policySchemaText);
  const contract = JSON.parse(contractText);
  const policy = JSON.parse(policyText);
  const fixtures = JSON.parse(fixturesText);
  const policyFixtures = JSON.parse(policyFixturesText);
  assertClosedObjects(manifestSchema, "manifest schema");
  assertClosedObjects(policySchema, "source-policy schema");
  const policyErrors = validateSourcePolicy(policy, policySchema, contract);
  if (policyErrors.length) {
    console.error("Source policy validation failed:");
    for (const error of policyErrors) console.error(`- ${error.code} ${error.path}: ${error.message}`);
    process.exitCode = 1;
    return;
  }
  assertContentContract(contract, policy);
  const policySha = createHash("sha256").update(policyText).digest("hex");
  const policyMismatches = [];
  for (const fixture of policyFixtures.cases) {
    const candidate = clone(policy);
    const candidateContract = clone(contract);
    for (const mutation of fixture.mutations ?? []) applyMutation(candidate, mutation);
    for (const mutation of fixture.contract_mutations ?? []) applyMutation(candidateContract, mutation);
    for (const sourceId of fixture.synchronize_policy_source_sha256 ?? []) {
      const source = candidate.sources.find((entry) => entry.id === sourceId);
      candidateContract.source_requirements[sourceId].policy_source_sha256 = semanticSha256(source);
    }
    const actual = sortedUnique(validateSourcePolicy(candidate, policySchema, candidateContract).map((error) => error.code));
    const expected = sortedUnique(fixture.expected_error_codes);
    if (!deepEqual(actual, expected)) policyMismatches.push({ name: fixture.name, expected, actual });
  }
  if (policyMismatches.length) {
    console.error(`Patch8 source-policy fixtures failed for ${policyMismatches.length}/${policyFixtures.cases.length} cases.`);
    for (const mismatch of policyMismatches) console.error(`- ${mismatch.name}\n  expected: ${mismatch.expected.join(", ") || "no errors"}\n  actual:   ${mismatch.actual.join(", ") || "no errors"}`);
    process.exitCode = 1;
    return;
  }
  const base = createFixtureManifest(contract, policy, policySha);
  const mismatches = [];
  for (const fixture of fixtures.cases) {
    const candidateContract = clone(contract);
    for (const mutation of fixture.contract_mutations ?? []) applyMutation(candidateContract, mutation);
    const manifest = fixture.contract_mutations?.length ? createFixtureManifest(candidateContract, policy, policySha) : clone(base);
    for (const mutation of fixture.mutations ?? []) applyMutation(manifest, mutation);
    const actual = sortedUnique(validateManifest(manifest, fixture.reader, manifestSchema, policy, candidateContract, policySha).map((error) => error.code));
    const expected = sortedUnique(fixture.expected_error_codes);
    if (!deepEqual(actual, expected)) mismatches.push({ name: fixture.name, expected, actual });
  }
  if (mismatches.length) {
    console.error(`Patch8 contract validation failed for ${mismatches.length}/${fixtures.cases.length} fixtures.`);
    for (const mismatch of mismatches) console.error(`- ${mismatch.name}\n  expected: ${mismatch.expected.join(", ") || "no errors"}\n  actual:   ${mismatch.actual.join(", ") || "no errors"}`);
    process.exitCode = 1;
    return;
  }
  console.log(`Patch8 source policy: ${policy.sources.length} registered sources; ${contract.required_source_ids.length} enabled v1 sources; ${policyFixtures.cases.length} fail-closed fixtures passed.`);
  console.log(`Patch8 manifest contract: ${fixtures.cases.length} fixtures passed (${Object.keys(contract.tables).length} exact table/read-model schemas).`);
};

await main();
