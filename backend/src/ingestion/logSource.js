'use strict';

/**
 * LogSource is the common abstraction every ingestion path implements:
 * FileUpload, Paste, SampleDataset (all implemented today), and
 * Elasticsearch (config/prep only - see elasticsearchClient.js). Each
 * source's job is simply to produce { rawText, filenameHint } for the
 * parsing stage; everything downstream (format detection, parsing, field
 * discovery, ...) is source-agnostic.
 */

function fromUpload(fileBuffer, originalFilename) {
  return {
    kind: 'file-upload',
    rawText: fileBuffer.toString('utf8'),
    filenameHint: originalFilename || '',
  };
}

function fromPaste(text) {
  return {
    kind: 'paste',
    rawText: text,
    filenameHint: '',
  };
}

function fromSampleDataset(name, rawText) {
  return {
    kind: 'sample-dataset',
    rawText,
    filenameHint: name,
  };
}

module.exports = { fromUpload, fromPaste, fromSampleDataset };
