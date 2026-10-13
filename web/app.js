"use strict";

const form = document.getElementById("lab-form");
const output = document.getElementById("output");
const statusElement = document.getElementById("status");
const runButton = document.getElementById("run");
let runtime = null;

function setStatus(message, isError = false) {
  statusElement.textContent = message;
  statusElement.classList.toggle("error", isError);
}
function parseCoefficients(value, maxLength) {
  if (!/^\s*-?\d+(?:\s*,\s*-?\d+)*\s*$/.test(value)) {
    throw new Error("Enter comma-separated integers (for example: 3,1,-4).");
  }
  const values = value.split(",").map((entry) => Number(entry.trim()));
  if (values.length > maxLength) {
    throw new Error("Too many coefficients for this preset (maximum " + maxLength + ").");
  }
  if (values.some((entry) => !Number.isSafeInteger(entry) || Math.abs(entry) > 1000000)) {
    throw new Error("Each coefficient must be an integer between -1,000,000 and 1,000,000.");
  }
  return values;
}

const PYTHON_EXPERIMENT = [
  "import json",
  "payload = json.loads(payload_json)",
  "params = BFVParams.from_preset(payload['preset'])",
  "a = payload['a'] + [0] * (params.N - len(payload['a']))",
  "b = payload['b'] + [0] * (params.N - len(payload['b']))",
  "scheme = BFVScheme(params)",
  "secret, public, relin = scheme.keygen()",
  "ct_a = scheme.encrypt(a, public)",
  "ct_b = scheme.encrypt(b, public)",
  "ct_sum = scheme.add(ct_a, ct_b)",
  "ct_prod = scheme.mul(ct_a, ct_b, relin)",
  "expected_a = [x % params.t for x in a]",
  "expected_b = [x % params.t for x in b]",
  "expected_sum = [(x+y) % params.t for x, y in zip(a,b)]",
  "expected_prod = (Poly(a,params.t,params.N) * Poly(b,params.t,params.N)).coeffs",
  "decrypted_a = scheme.decrypt(ct_a, secret)",
  "decrypted_b = scheme.decrypt(ct_b, secret)",
  "decrypted_sum = scheme.decrypt(ct_sum, secret)",
  "decrypted_prod = scheme.decrypt(ct_prod, secret)",
  "result_json = json.dumps({",
  " 'parameters': {'N': params.N, 'q': params.q, 't': params.t},",
  " 'ciphertext_A_c0_first_four': ct_a.c0.coeffs[:4],",
  " 'ciphertext_B_c0_first_four': ct_b.c0.coeffs[:4],",
  " 'decrypt_A': decrypted_a[:len(payload['a'])],",
  " 'decrypt_B': decrypted_b[:len(payload['b'])],",
  " 'add_decrypted': decrypted_sum,",
  " 'add_expected': expected_sum,",
  " 'add_correct': decrypted_sum == expected_sum,",
  " 'multiply_decrypted': decrypted_prod,",
  " 'multiply_expected': expected_prod,",
  " 'multiply_correct': decrypted_prod == expected_prod",
  "})",
  "result_json"
].join("\n");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!runtime) return;
  try {
    const preset = document.getElementById("preset").value;
    const maximum = preset === "toy" ? 16 : 64;
    const a = parseCoefficients(document.getElementById("message-a").value, maximum);
    const b = parseCoefficients(document.getElementById("message-b").value, maximum);
    runButton.disabled = true;
    setStatus("Running encryption and ring operations locally…");
    runtime.globals.set("payload_json", JSON.stringify({ preset, a, b }));
    const result = JSON.parse(await runtime.runPythonAsync(PYTHON_EXPERIMENT));
    output.textContent = JSON.stringify(result, null, 2);
    setStatus(result.add_correct && result.multiply_correct ?
      "Completed — both arithmetic checks passed." :
      "Completed — at least one check failed; these parameters have limited noise capacity.",
      !(result.add_correct && result.multiply_correct));
  } catch (error) {
    setStatus("Experiment failed: " + String(error), true);
    output.textContent = "No valid result was produced.";
  } finally {
    runButton.disabled = false;
  }
});

async function initialize() {
  try {
    if (typeof loadPyodide !== "function") {
      throw new Error("Pyodide script could not be loaded (check internet access).");
    }
    const [py, response] = await Promise.all([loadPyodide(), fetch("./bfv_engine.py")]);
    if (!response.ok) {
      throw new Error("Python engine asset is missing (HTTP " + response.status + ").");
    }
    await py.runPythonAsync(await response.text());
    runtime = py;
    runButton.disabled = false;
    runButton.textContent = "Encrypt and evaluate";
    setStatus("Ready. Python executes inside this browser tab.");
  } catch (error) {
    runButton.textContent = "Runtime unavailable";
    setStatus("Cannot initialize the local Python engine: " + String(error), true);
  }
}
initialize();
