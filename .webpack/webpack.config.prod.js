const {
    externals,
    helpers,
    plugins,
    presets
} = require('@humanmade/webpack-helpers');

const {
    filePath
} = helpers;

module.exports = presets.production({
    name: 'wikimedia-wordpress-security-plugin',
    externals: {
        ...externals,
    },
    plugins: [
        plugins.clean(),
    ],
    cache: {
        type: 'filesystem',
    },
});
