const webpack = require('webpack');

module.exports = function override(config, env) {
  // Aseguramos que el objeto fallback exista
  config.resolve.fallback = {
    ...config.resolve.fallback,
    "assert": require.resolve("assert/"),
    "buffer": require.resolve("buffer/"),
    "crypto": require.resolve("crypto-browserify"),
    "path": require.resolve("path-browserify"),
    "stream": require.resolve("stream-browserify"),
    "vm": require.resolve("vm-browserify"),
    "fs": false,
    // --- LÍNEA CLAVE AÑADIDA GRACIAS A TU INVESTIGACIÓN ---
    'process/browser': require.resolve('process/browser')
  };

  // Mantenemos el plugin para proveer las variables globales
  config.plugins = (config.plugins || []).concat([
    new webpack.ProvidePlugin({
      process: 'process/browser',
      Buffer: ['buffer', 'Buffer'],
    }),
  ]);

  config.ignoreWarnings = [/Failed to parse source map/];

  return config;
};