const tl = require("azure-pipelines-task-lib/task");
const cp = require("child_process");
const fs = require("fs");

function execCommand(command, args) {
  const result = cp.spawnSync(command, args, { encoding: "utf8" });
  if (result.error) {
    throw result.error;
  }
  return result;
}

function toLevel(severity) {
  if (severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function buildSarif(findings) {
  const rules = {};
  const results = findings.map((finding) => {
    const ruleId = finding.rule_id || "UNKNOWN";
    rules[ruleId] = { id: ruleId, name: ruleId };
    const result = {
      ruleId,
      level: toLevel(finding.severity || "low"),
      message: { text: finding.message || "" },
    };
    if (finding.path) {
      result.locations = [
        { physicalLocation: { artifactLocation: { uri: finding.path } } },
      ];
    }
    return result;
  });

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Terraform Guardrail MCP",
            informationUri: "https://github.com/Huzefaaa2/terraform-guardrail",
            rules: Object.values(rules),
          },
        },
        results,
      },
    ],
  };
}

function buildJUnit(findings) {
  const failures = findings.filter((f) => f.severity !== "low").length;
  const skipped = findings.filter((f) => f.severity === "low").length;
  let xml = "";
  xml += '<?xml version="1.0" encoding="utf-8"?>\n';
  xml += `<testsuite name="terraform-guardrail" tests="${findings.length}" failures="${failures}" skipped="${skipped}">\n`;
  for (const finding of findings) {
    const ruleId = finding.rule_id || "UNKNOWN";
    const message = finding.message || "";
    const path = finding.path || "";
    const detail = path ? `${message} (${path})` : message;
    xml += `  <testcase classname="${ruleId}" name="${message}">`;
    if (finding.severity === "low") {
      xml += `<skipped message="${detail}" />`;
    } else {
      xml += `<failure message="${detail}">${detail}</failure>`;
    }
    xml += "</testcase>\n";
  }
  xml += "</testsuite>\n";
  return xml;
}

try {
  const path = tl.getInput("path", true);
  const state = tl.getInput("state", false);
  const schema = tl.getBoolInput("schema", false);
  const failOn = tl.getInput("failOn", true);
  const policyBundle = tl.getInput("policyBundle", false);
  const policyRegistry = tl.getInput("policyRegistry", false);
  const policyQuery = tl.getInput("policyQuery", false);
  const python = tl.getInput("python", true);
  const jsonReport = tl.getInput("jsonReport", true);
  const sarifReport = tl.getInput("sarifReport", true);
  const junitReport = tl.getInput("junitReport", true);

  execCommand(python, ["-m", "pip", "install", "--upgrade", "pip"]);
  execCommand(python, ["-m", "pip", "install", "--upgrade", "terraform-guardrail"]);

  const args = ["scan", path, "--format", "json", "--fail-on", failOn];
  if (schema) args.push("--schema");
  if (state) args.push("--state", state);
  if (policyBundle) args.push("--policy-bundle", policyBundle);
  if (policyRegistry) args.push("--policy-registry", policyRegistry);
  if (policyQuery) args.push("--policy-query", policyQuery);

  const result = execCommand("terraform-guardrail", args);
  fs.writeFileSync(jsonReport, result.stdout || "");

  let report = {};
  try {
    report = JSON.parse(result.stdout || "{}");
  } catch (err) {
    tl.warning("Failed to parse JSON output.");
  }

  const findings = report.findings || [];
  const sarif = buildSarif(findings);
  fs.writeFileSync(sarifReport, JSON.stringify(sarif, null, 2));
  fs.writeFileSync(junitReport, buildJUnit(findings));

  if (result.status !== 0) {
    tl.setResult(
      tl.TaskResult.Failed,
      `Terraform Guardrail found policy violations (exit ${result.status}).`
    );
  } else {
    tl.setResult(tl.TaskResult.Succeeded, "Terraform Guardrail scan complete.");
  }
} catch (err) {
  tl.setResult(tl.TaskResult.Failed, err.message);
}
