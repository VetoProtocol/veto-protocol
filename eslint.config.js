import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/.next/**',
      '**/coverage/**',
      // Third-party bundles shipped as-is. Linting somebody else's minified
      // build reports thousands of findings nobody can act on.
      '**/vendor/**',
      // Exported copies of the design mockup. Not source.
      'MockUpp/**',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      // Authorization code must not silently widen types or swallow failures.
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-non-null-assertion': 'error',
      'no-console': ['error', { allow: ['warn', 'error'] }],
      eqeqeq: ['error', 'always'],
    },
  },
  {
    // Build configuration runs in Node before any bundler sees it, so the Node
    // globals are real here even though nothing in src/ may use them freely.
    files: ['**/*.mjs', '**/*.config.js'],
    languageOptions: { globals: { process: 'readonly', console: 'readonly' } },
  },
  {
    // Tests only. A non-null assertion in production authorization code can let
    // an unchecked value cross a trust boundary; in a test the worst case is a
    // failing assertion, which is the point of a test.
    files: ['**/test/**/*.ts', '**/*.test.ts'],
    rules: { '@typescript-eslint/no-non-null-assertion': 'off' },
  },
);
