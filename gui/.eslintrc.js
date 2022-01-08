module.exports = {
  root: true,

  env: {
    node: true
  },

  extends: [
    'plugin:vue/essential',
    '@vue/standard',
    '@vue/typescript/recommended'
  ],

  parserOptions: {
    ecmaVersion: 2020
  },

  rules: {
    'no-console': process.env.NODE_ENV === 'production' ? 'warn' : 'off',
    'no-debugger': process.env.NODE_ENV === 'production' ? 'warn' : 'off',
    'space-before-function-paren': [
      'error',
      'never'
    ],
    "generator-star-spacing": ["error", {"before": false, "after": true}]
  },

  'extends': [
    'plugin:vue/essential',
    '@vue/standard',
    '@vue/typescript/recommended',
    'eslint:recommended'
  ]
}
