#!/usr/bin/env node

import { readFile } from "node:fs/promises";

const SCHEMA_URL = new URL("../contracts/dataset-manifest.schema.json", import.meta.url);
const FIXTURES_URL = new URL(
  "../contracts/fixtures/dataset-manifest.cases.json",
  import.meta.url,
);

const SAFE_SOURCE_KEYS = [
  "source_id",
  "terms_reviewed_at",
  "acquired_at",
  "watermark",
  "input_sha256",
  "field_rules",
  "notice_ref",
];
const DATASETS = ["patch8", "threat10"];
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const REVISION_PATTERN = /^[0-9a-f]{40}$/;

const isObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const hasOwn = (value, key) =>
  Object.prototype.hasOwnProperty.call(value, key);

const pointerPart = (value) =>
  String(value).replaceAll("~", "~0").replaceAll("/", "~1");

const childPath = (path, key) => `${path}/${pointerPart(key)}`;

const stableStringify = (value) => {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (isObject(value)) {
    const entries = Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${stableStringify(value[key])}`,
      );
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
};

const deepEqual = (left, right) =>
  stableStringify(left) === stableStringify(right);

const isType = (value, type) => {
  switch (type) {
    case "array":
      return Array.isArray(value);
    case "boolean":
      return typeof value === "boolean";
    case "integer":
      return Number.isInteger(value);
    case "null":
      return value === null;
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "object":
      return isObject(value);
    case "string":
      return typeof value === "string";
    default:
      return false;
  }
};

const isCalendarDate = (value) => {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
};

const isDateTime = (value) => {
  const match = /^(\d{4}-\d{2}-\d{2})T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.exec(
    value,
  );
  return Boolean(match && isCalendarDate(match[1]) && !Number.isNaN(Date.parse(value)));
};

const isUri = (value) => {
  try {
    const parsed = new URL(value);
    return Boolean(parsed.protocol && parsed.hostname);
  } catch {
    return false;
  }
};

const resolveRef = (rootSchema, ref) => {
  if (!ref.startsWith("#/")) {
    throw new Error(`Only local JSON Schema references are supported: ${ref}`);
  }
  return ref
    .slice(2)
    .split("/")
    .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce((current, part) => current?.[part], rootSchema);
};

const validateSchemaNode = (value, node, rootSchema, path = "") => {
  if (node === true) return [];
  if (node === false) {
    return [{ path, keyword: "falseSchema", message: "value is forbidden" }];
  }
  if (!isObject(node)) {
    throw new Error(`Invalid JSON Schema node at ${path || "/"}`);
  }
  if (node.$ref) {
    const target = resolveRef(rootSchema, node.$ref);
    if (!target) throw new Error(`Unresolved JSON Schema reference: ${node.$ref}`);
    return validateSchemaNode(value, target, rootSchema, path);
  }

  const issues = [];
  const add = (keyword, message, issuePath = path) => {
    issues.push({ path: issuePath, keyword, message });
  };

  if (node.oneOf) {
    const branchResults = node.oneOf.map((branch) =>
      validateSchemaNode(value, branch, rootSchema, path),
    );
    if (branchResults.filter((result) => result.length === 0).length !== 1) {
      add("oneOf", "value must match exactly one schema branch");
    }
    return issues;
  }

  if (node.type !== undefined) {
    const allowedTypes = Array.isArray(node.type) ? node.type : [node.type];
    if (!allowedTypes.some((type) => isType(value, type))) {
      add("type", `expected ${allowedTypes.join(" or ")}`);
      return issues;
    }
  }

  if (hasOwn(node, "const") && !deepEqual(value, node.const)) {
    add("const", `expected ${JSON.stringify(node.const)}`);
  }
  if (node.enum && !node.enum.some((candidate) => deepEqual(value, candidate))) {
    add("enum", "value is not in the allowed enumeration");
  }

  if (typeof value === "string") {
    if (node.minLength !== undefined && value.length < node.minLength) {
      add("minLength", `minimum string length is ${node.minLength}`);
    }
    if (node.maxLength !== undefined && value.length > node.maxLength) {
      add("maxLength", `maximum string length is ${node.maxLength}`);
    }
    if (node.pattern !== undefined && !new RegExp(node.pattern).test(value)) {
      add("pattern", `value does not match ${node.pattern}`);
    }
    if (node.format === "date" && !isCalendarDate(value)) {
      add("format", "value is not a valid RFC 3339 full-date");
    }
    if (node.format === "date-time" && !isDateTime(value)) {
      add("format", "value is not a valid RFC 3339 date-time");
    }
    if (node.format === "uri" && !isUri(value)) {
      add("format", "value is not an absolute URI");
    }
  }

  if (typeof value === "number") {
    if (node.minimum !== undefined && value < node.minimum) {
      add("minimum", `minimum value is ${node.minimum}`);
    }
  }

  if (Array.isArray(value)) {
    if (node.minItems !== undefined && value.length < node.minItems) {
      add("minItems", `minimum array length is ${node.minItems}`);
    }
    if (node.uniqueItems) {
      const encoded = value.map((item) => stableStringify(item));
      if (new Set(encoded).size !== encoded.length) {
        add("uniqueItems", "array items must be unique");
      }
    }
    if (node.items !== undefined) {
      value.forEach((item, index) => {
        issues.push(
          ...validateSchemaNode(
            item,
            node.items,
            rootSchema,
            childPath(path, index),
          ),
        );
      });
    }
  }

  if (isObject(value)) {
    const properties = node.properties ?? {};
    const patterns = Object.entries(node.patternProperties ?? {}).map(
      ([pattern, child]) => [new RegExp(pattern), child],
    );
    for (const required of node.required ?? []) {
      if (!hasOwn(value, required)) {
        add("required", "required property is missing", childPath(path, required));
      }
    }
    for (const [key, child] of Object.entries(value)) {
      const propertySchema = properties[key];
      const patternSchemas = patterns
        .filter(([pattern]) => pattern.test(key))
        .map(([, patternSchema]) => patternSchema);
      if (propertySchema !== undefined) {
        issues.push(
          ...validateSchemaNode(
            child,
            propertySchema,
            rootSchema,
            childPath(path, key),
          ),
        );
      }
      for (const patternSchema of patternSchemas) {
        issues.push(
          ...validateSchemaNode(
            child,
            patternSchema,
            rootSchema,
            childPath(path, key),
          ),
        );
      }
      if (
        propertySchema === undefined &&
        patternSchemas.length === 0 &&
        node.additionalProperties === false
      ) {
        add(
          "additionalProperties",
          "additional property is not allowed",
          childPath(path, key),
        );
      }
    }
  }

  return issues;
};

const structuralErrorCode = ({ path }) => {
  if (path === "/manifest_version") return "MANIFEST_VERSION_UNSUPPORTED";
  if (path.startsWith("/previous_release")) return "PREVIOUS_RELEASE_INVALID";
  if (/^\/artifacts\/\d+\/sha256$/.test(path)) {
    return "ARTIFACT_CHECKSUM_INVALID";
  }
  if (/^\/artifacts\/\d+\/relative_path$/.test(path)) return "PATH_UNSAFE";
  if (/^\/artifacts\/\d+\/source_ids/.test(path)) {
    return "ARTIFACT_SOURCE_IDS_MISSING";
  }
  if (path === "/builder/deterministic") return "BUILDER_NONDETERMINISTIC";
  if (/^\/provenance\/sources\/\d+\/field_rules/.test(path)) {
    return "FIELD_RULES_MISSING";
  }
  if (/^\/provenance\/sources\/\d+\/input_sha256$/.test(path)) {
    return "PROVENANCE_INPUT_CHECKSUM_INVALID";
  }
  if (path === "/provenance/source_policy/sha256") {
    return "SOURCE_POLICY_CHECKSUM_INVALID";
  }
  if (/^\/provenance\/reproducibility\/.*digest_sha256$/.test(path)) {
    return "REPRODUCIBILITY_DIGEST_INVALID";
  }
  if (/^\/table_schemas\/\d+\/schema_sha256$/.test(path)) {
    return "TABLE_SCHEMA_CHECKSUM_INVALID";
  }
  if (path === "/storage/immutable_revision") return "STORAGE_REVISION_INVALID";
  if (path === "/storage/base_url") return "STORAGE_REVISION_MISMATCH";
  return "MANIFEST_STRUCTURE_INVALID";
};

const duplicateValues = (values) => {
  const seen = new Set();
  const duplicates = new Set();
  for (const value of values) {
    if (seen.has(value)) duplicates.add(value);
    seen.add(value);
  }
  return duplicates;
};

const validateManifest = (manifest, reader, schema) => {
  const errors = [];
  const add = (code, path, message) => errors.push({ code, path, message });

  for (const issue of validateSchemaNode(manifest, schema, schema)) {
    add(structuralErrorCode(issue), issue.path || "/", issue.message);
  }

  if (!isObject(manifest)) return errors;

  if (manifest.manifest_version !== 1) {
    add(
      "MANIFEST_VERSION_UNSUPPORTED",
      "/manifest_version",
      "only manifest version 1 is supported",
    );
  }

  const compatibility = manifest.compatibility;
  if (isObject(compatibility)) {
    const manifestMin = compatibility.min_reader_manifest_version;
    const manifestMax = compatibility.max_reader_manifest_version;
    const schemaMin = compatibility.min_reader_schema_version;
    const schemaMax = compatibility.max_reader_schema_version;
    if (
      Number.isInteger(manifestMin) &&
      Number.isInteger(manifestMax) &&
      manifestMin > manifestMax
    ) {
      add(
        "COMPATIBILITY_RANGE_INVALID",
        "/compatibility",
        "minimum manifest reader version exceeds maximum",
      );
    }
    if (
      Number.isInteger(schemaMin) &&
      Number.isInteger(schemaMax) &&
      schemaMin > schemaMax
    ) {
      add(
        "COMPATIBILITY_RANGE_INVALID",
        "/compatibility",
        "minimum schema reader version exceeds maximum",
      );
    }
    if (
      Number.isInteger(reader?.manifest_version) &&
      Number.isInteger(manifestMin) &&
      Number.isInteger(manifestMax) &&
      (reader.manifest_version < manifestMin || reader.manifest_version > manifestMax)
    ) {
      add(
        "MANIFEST_VERSION_UNSUPPORTED",
        "/compatibility",
        "reader manifest version is outside the compatible range",
      );
    }
    if (
      Number.isInteger(reader?.schema_version) &&
      Number.isInteger(schemaMin) &&
      Number.isInteger(schemaMax) &&
      (reader.schema_version < schemaMin || reader.schema_version > schemaMax)
    ) {
      add(
        "SCHEMA_VERSION_UNSUPPORTED",
        "/compatibility",
        "reader schema version is outside the compatible range",
      );
    }
  }

  const storage = manifest.storage;
  if (isObject(storage)) {
    const expectedBase = `https://huggingface.co/datasets/${storage.repository}/resolve/${storage.immutable_revision}/`;
    if (storage.base_url !== expectedBase) {
      add(
        "STORAGE_REVISION_MISMATCH",
        "/storage/base_url",
        "storage base URL does not pin the declared repository revision",
      );
    }
  }

  const previous = manifest.previous_release;
  if (isObject(previous) && isObject(storage)) {
    const expectedUrl = `https://huggingface.co/datasets/${storage.repository}/resolve/${previous.immutable_revision}/dataset-manifest.json`;
    if (
      previous.release_id === manifest.release_id ||
      previous.immutable_revision === storage.immutable_revision ||
      previous.manifest_url !== expectedUrl ||
      !SHA256_PATTERN.test(previous.manifest_sha256 ?? "") ||
      !REVISION_PATTERN.test(previous.immutable_revision ?? "")
    ) {
      add(
        "PREVIOUS_RELEASE_INVALID",
        "/previous_release",
        "previous release must identify a distinct checksummed manifest at its pinned revision",
      );
    }
  }

  if (manifest.builder?.deterministic !== true) {
    add(
      "BUILDER_NONDETERMINISTIC",
      "/builder/deterministic",
      "release builders must be deterministic",
    );
  }

  const tableSchemas = Array.isArray(manifest.table_schemas)
    ? manifest.table_schemas.filter(isObject)
    : [];
  const routingEntries = Array.isArray(manifest.routing)
    ? manifest.routing.filter(isObject)
    : [];
  const artifacts = Array.isArray(manifest.artifacts)
    ? manifest.artifacts.filter(isObject)
    : [];
  const provenanceSources = Array.isArray(manifest.provenance?.sources)
    ? manifest.provenance.sources.filter(isObject)
    : [];
  const notices = Array.isArray(manifest.provenance?.notices)
    ? manifest.provenance.notices.filter(isObject)
    : [];

  const schemasById = new Map(tableSchemas.map((entry) => [entry.id, entry]));
  const routesBySchema = new Map();
  for (const route of routingEntries) {
    const current = routesBySchema.get(route.schema_id) ?? [];
    current.push(route);
    routesBySchema.set(route.schema_id, current);
  }
  const sourcesById = new Map(
    provenanceSources.map((source) => [source.source_id, source]),
  );
  const noticesById = new Map(notices.map((notice) => [notice.id, notice]));

  for (const duplicate of duplicateValues(tableSchemas.map((entry) => entry.id))) {
    add("TABLE_SCHEMA_ID_DUPLICATE", "/table_schemas", `duplicate schema id ${duplicate}`);
  }
  for (const duplicate of duplicateValues(routingEntries.map((entry) => entry.schema_id))) {
    add("ROUTING_DUPLICATE", "/routing", `duplicate routing entry for ${duplicate}`);
  }
  for (const duplicate of duplicateValues(artifacts.map((entry) => entry.id))) {
    add("ARTIFACT_ID_DUPLICATE", "/artifacts", `duplicate artifact id ${duplicate}`);
  }
  for (const duplicate of duplicateValues(
    artifacts.map((entry) => entry.relative_path),
  )) {
    add("ARTIFACT_PATH_DUPLICATE", "/artifacts", `duplicate artifact path ${duplicate}`);
  }
  for (const duplicate of duplicateValues(
    provenanceSources.map((entry) => entry.source_id),
  )) {
    add(
      "PROVENANCE_SOURCE_DUPLICATE",
      "/provenance/sources",
      `duplicate provenance source ${duplicate}`,
    );
  }
  for (const duplicate of duplicateValues(notices.map((entry) => entry.id))) {
    add("NOTICE_ID_DUPLICATE", "/provenance/notices", `duplicate notice id ${duplicate}`);
  }

  for (const table of tableSchemas) {
    const fieldNames = Array.isArray(table.fields)
      ? table.fields.filter(isObject).map((field) => field.name)
      : [];
    const fieldSet = new Set(fieldNames);
    for (const duplicate of duplicateValues(fieldNames)) {
      add(
        "TABLE_FIELD_NAME_DUPLICATE",
        `/table_schemas/${pointerPart(table.id)}/fields`,
        `duplicate field name ${duplicate}`,
      );
    }
    for (const key of table.primary_key ?? []) {
      if (!fieldSet.has(key)) {
        add(
          "PRIMARY_KEY_FIELD_UNKNOWN",
          `/table_schemas/${pointerPart(table.id)}/primary_key`,
          `primary key field ${key} is not defined`,
        );
      }
    }
    for (const key of table.sort_keys ?? []) {
      if (!fieldSet.has(key)) {
        add(
          "SORT_KEY_FIELD_UNKNOWN",
          `/table_schemas/${pointerPart(table.id)}/sort_keys`,
          `sort field ${key} is not defined`,
        );
      }
    }

    const routes = routesBySchema.get(table.id) ?? [];
    if (routes.length === 0) {
      add("ROUTING_MISSING", "/routing", `schema ${table.id} has no routing entry`);
    }
    if (routes.length > 1) {
      add("ROUTING_DUPLICATE", "/routing", `schema ${table.id} has multiple routing entries`);
    }
    if (!artifacts.some((artifact) => artifact.schema_id === table.id)) {
      add(
        "ARTIFACT_SCHEMA_EMPTY",
        "/artifacts",
        `schema ${table.id} has no artifact`,
      );
    }
  }

  for (const route of routingEntries) {
    const table = schemasById.get(route.schema_id);
    if (!table) {
      add(
        "ROUTING_SCHEMA_UNKNOWN",
        "/routing",
        `routing references unknown schema ${route.schema_id}`,
      );
      continue;
    }
    const fieldSet = new Set(
      Array.isArray(table.fields)
        ? table.fields.filter(isObject).map((field) => field.name)
        : [],
    );
    const dimensions = Array.isArray(route.dimensions)
      ? route.dimensions.filter(isObject)
      : [];
    for (const duplicate of duplicateValues(
      dimensions.map((dimension) => dimension.partition_key),
    )) {
      add(
        "PARTITION_KEY_DUPLICATE",
        "/routing",
        `routing for ${route.schema_id} repeats partition key ${duplicate}`,
      );
    }
    for (const dimension of dimensions) {
      if (!fieldSet.has(dimension.source_field)) {
        add(
          "ROUTING_SOURCE_FIELD_UNKNOWN",
          "/routing",
          `routing source field ${dimension.source_field} is not in ${route.schema_id}`,
        );
      }
    }
  }

  const safeRelativePath = new RegExp(schema.$defs.relativePath.pattern);
  for (const artifact of artifacts) {
    const table = schemasById.get(artifact.schema_id);
    if (!table) {
      add(
        "ARTIFACT_SCHEMA_UNKNOWN",
        "/artifacts",
        `artifact ${artifact.id} references unknown schema ${artifact.schema_id}`,
      );
    } else if (artifact.schema_version !== table.version) {
      add(
        "ARTIFACT_SCHEMA_VERSION_MISMATCH",
        "/artifacts",
        `artifact ${artifact.id} schema version does not match ${table.id}`,
      );
    }

    const route = (routesBySchema.get(artifact.schema_id) ?? [])[0];
    if (route && isObject(artifact.partition_values)) {
      const dimensions = Array.isArray(route.dimensions)
        ? route.dimensions.filter(isObject)
        : [];
      const expectedKeys = new Set(
        dimensions.map((dimension) => dimension.partition_key),
      );
      const actualKeys = new Set(Object.keys(artifact.partition_values));
      for (const key of expectedKeys) {
        if (!actualKeys.has(key)) {
          add(
            "PARTITION_KEY_MISSING",
            "/artifacts",
            `artifact ${artifact.id} is missing partition key ${key}`,
          );
        }
      }
      for (const key of actualKeys) {
        if (!expectedKeys.has(key)) {
          add(
            "PARTITION_KEY_UNEXPECTED",
            "/artifacts",
            `artifact ${artifact.id} has unexpected partition key ${key}`,
          );
        }
      }
    }

    const pathIsSafe =
      typeof artifact.relative_path === "string" &&
      safeRelativePath.test(artifact.relative_path);
    if (!pathIsSafe) {
      add("PATH_UNSAFE", "/artifacts", `artifact ${artifact.id} has an unsafe path`);
    } else if (typeof storage?.base_url === "string") {
      let inheritedUrl;
      try {
        inheritedUrl = new URL(artifact.relative_path, storage.base_url).href;
      } catch {
        add(
          "STORAGE_REVISION_MISMATCH",
          "/artifacts",
          `artifact ${artifact.id} cannot inherit an invalid storage base URL`,
        );
      }
      if (inheritedUrl && !inheritedUrl.startsWith(storage.base_url)) {
        add(
          "STORAGE_REVISION_MISMATCH",
          "/artifacts",
          `artifact ${artifact.id} escapes the immutable storage revision`,
        );
      }
    }

    if (!Array.isArray(artifact.source_ids) || artifact.source_ids.length === 0) {
      add(
        "ARTIFACT_SOURCE_IDS_MISSING",
        "/artifacts",
        `artifact ${artifact.id} has no provenance source ids`,
      );
    } else {
      for (const sourceId of artifact.source_ids) {
        if (!sourcesById.has(sourceId)) {
          add(
            "PROVENANCE_SOURCE_UNKNOWN",
            "/artifacts",
            `artifact ${artifact.id} references unknown source ${sourceId}`,
          );
        }
      }
    }
  }

  for (const source of provenanceSources) {
    if (!Array.isArray(source.field_rules) || source.field_rules.length === 0) {
      add(
        "FIELD_RULES_MISSING",
        "/provenance/sources",
        `source ${source.source_id} has no field-level policy rules`,
      );
    }
    const notice = noticesById.get(source.notice_ref);
    if (!notice) {
      add(
        "NOTICE_REF_UNKNOWN",
        "/provenance/sources",
        `source ${source.source_id} references unknown notice ${source.notice_ref}`,
      );
    } else if (notice.source_id !== source.source_id) {
      add(
        "NOTICE_SOURCE_MISMATCH",
        "/provenance/notices",
        `notice ${notice.id} belongs to a different source`,
      );
    }
  }

  for (const notice of notices) {
    if (!sourcesById.has(notice.source_id)) {
      add(
        "NOTICE_SOURCE_UNKNOWN",
        "/provenance/notices",
        `notice ${notice.id} references unknown source ${notice.source_id}`,
      );
    }
  }

  return errors;
};

const assertSchemaSentinel = (schema) => {
  const failures = [];
  if (schema.$schema !== "https://json-schema.org/draft/2020-12/schema") {
    failures.push("schema draft must be JSON Schema 2020-12");
  }
  if (schema.properties?.manifest_version?.const !== 1) {
    failures.push("manifest_version must be const 1");
  }
  if (!deepEqual(schema.properties?.dataset?.enum, DATASETS)) {
    failures.push("dataset enum must be exactly patch8 and threat10");
  }
  const requiredSourceKeys = new Set(schema.$defs?.sourceRecord?.required ?? []);
  for (const key of SAFE_SOURCE_KEYS) {
    if (!requiredSourceKeys.has(key)) failures.push(`sourceRecord must require ${key}`);
  }

  const visit = (node, path = "#") => {
    if (Array.isArray(node)) {
      node.forEach((child, index) => visit(child, `${path}/${index}`));
      return;
    }
    if (!isObject(node)) return;
    if (node.type === "object" && node.additionalProperties !== false) {
      failures.push(`${path} must set additionalProperties:false`);
    }
    for (const [key, child] of Object.entries(node)) {
      visit(child, `${path}/${pointerPart(key)}`);
    }
  };
  visit(schema);

  if (failures.length > 0) {
    throw new Error(`Dataset schema sentinel failed:\n- ${failures.join("\n- ")}`);
  }
};

const sortedUnique = (values) => [...new Set(values)].sort();

const main = async () => {
  const [schemaText, fixturesText] = await Promise.all([
    readFile(SCHEMA_URL, "utf8"),
    readFile(FIXTURES_URL, "utf8"),
  ]);
  const schema = JSON.parse(schemaText);
  const fixtures = JSON.parse(fixturesText);
  assertSchemaSentinel(schema);

  if (fixtures.schema_version !== 1 || !Array.isArray(fixtures.cases)) {
    throw new Error("Fixture collection must use schema_version 1 and contain cases");
  }

  const mismatches = [];
  let validCount = 0;
  let invalidCount = 0;
  for (const fixture of fixtures.cases) {
    if (
      !isObject(fixture) ||
      typeof fixture.name !== "string" ||
      typeof fixture.expected_valid !== "boolean" ||
      !Array.isArray(fixture.expected_error_codes) ||
      !isObject(fixture.reader)
    ) {
      throw new Error("Every fixture must define name, expectation, reader, and manifest");
    }
    const errors = validateManifest(fixture.manifest, fixture.reader, schema);
    const actualCodes = sortedUnique(errors.map((error) => error.code));
    const expectedCodes = sortedUnique(fixture.expected_error_codes);
    if (fixture.expected_valid) validCount += 1;
    else invalidCount += 1;

    const expectationMatches = fixture.expected_valid
      ? actualCodes.length === 0 && expectedCodes.length === 0
      : deepEqual(actualCodes, expectedCodes);
    if (!expectationMatches) {
      mismatches.push({
        name: fixture.name,
        expected: fixture.expected_valid ? [] : expectedCodes,
        actual: actualCodes,
        errors,
      });
    }
  }

  if (mismatches.length > 0) {
    console.error(
      `Dataset contract validation failed for ${mismatches.length}/${fixtures.cases.length} fixtures.`,
    );
    for (const mismatch of mismatches) {
      console.error(`\n${mismatch.name}`);
      console.error(`  expected: ${mismatch.expected.join(", ") || "no errors"}`);
      console.error(`  actual:   ${mismatch.actual.join(", ") || "no errors"}`);
      for (const error of mismatch.errors) {
        console.error(`  - ${error.code} ${error.path}: ${error.message}`);
      }
    }
    process.exitCode = 1;
    return;
  }

  console.log(
    `Dataset contract: ${fixtures.cases.length} fixtures passed (${validCount} valid, ${invalidCount} invalid).`,
  );
};

await main();
