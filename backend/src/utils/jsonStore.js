const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');

function filePath(name) {
  return path.join(DATA_DIR, `${name}.json`);
}

function ensureFile(name, defaultValue) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  const fp = filePath(name);
  if (!fs.existsSync(fp)) {
    fs.writeFileSync(fp, JSON.stringify(defaultValue, null, 2));
  }
  return fp;
}

/**
 * Read a JSON "collection" file, creating it with `defaultValue` if missing.
 */
function readCollection(name, defaultValue = []) {
  const fp = ensureFile(name, defaultValue);
  const raw = fs.readFileSync(fp, 'utf-8');
  try {
    return JSON.parse(raw);
  } catch (_) {
    return defaultValue;
  }
}

/**
 * Overwrite a JSON "collection" file with new contents.
 */
function writeCollection(name, data) {
  ensureFile(name, data);
  fs.writeFileSync(filePath(name), JSON.stringify(data, null, 2));
  return data;
}

/**
 * Append one record to a collection (array) and persist it, capping length.
 */
function appendRecord(name, record, { maxLength = 5000 } = {}) {
  const collection = readCollection(name, []);
  collection.push(record);
  const trimmed = collection.length > maxLength ? collection.slice(collection.length - maxLength) : collection;
  writeCollection(name, trimmed);
  return record;
}

module.exports = { readCollection, writeCollection, appendRecord, DATA_DIR };
