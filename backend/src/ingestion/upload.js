'use strict';

const multer = require('multer');
const path = require('path');
const config = require('../config/env');

class UploadValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UploadValidationError';
  }
}

const storage = multer.memoryStorage();

function fileFilter(_req, file, cb) {
  const ext = path.extname(file.originalname || '').toLowerCase();
  if (!config.upload.allowedExtensions.includes(ext)) {
    cb(new UploadValidationError(`File extension "${ext}" is not allowed. Allowed: ${config.upload.allowedExtensions.join(', ')}`));
    return;
  }
  // Belt-and-suspenders MIME check; browsers/log-export tools are
  // inconsistent about content-type, so this only rejects clearly wrong
  // categories (binary/executable) rather than requiring an exact match.
  const rejectedMimePrefixes = ['application/x-msdownload', 'application/x-executable', 'application/x-sh'];
  if (rejectedMimePrefixes.some((prefix) => (file.mimetype || '').startsWith(prefix))) {
    cb(new UploadValidationError(`File content-type "${file.mimetype}" is not allowed for log ingestion.`));
    return;
  }
  cb(null, true);
}

const upload = multer({
  storage,
  limits: {
    fileSize: config.upload.maxFileSizeBytes,
    files: 1,
  },
  fileFilter,
});

module.exports = { upload, UploadValidationError };
