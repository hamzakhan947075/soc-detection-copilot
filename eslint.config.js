'use strict';

const js = require('./backend/node_modules/@eslint/js');
const globals = require('./backend/node_modules/globals');

module.exports = [
  js.configs.recommended,
  {
    ignores: ['**/node_modules/**', 'backend/data/**'],
  },
  {
    files: ['backend/src/**/*.js', 'backend/tests/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: { ...globals.node, ...globals.jest },
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' }],
    },
  },
  {
    files: ['frontend/js/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.browser },
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' }],
    },
  },
];
