const { externals, helpers, presets } = require( '@humanmade/webpack-helpers' );

const { choosePort, cleanOnExit, filePath } = helpers;

cleanOnExit( [
	filePath( 'build', 'development-asset-manifest.json' ),
] );

module.exports = choosePort( 9090 ).then( ( port ) => presets.development( {
	name: 'vegalite-plugin-editor',
	devServer: {
		server: 'https',
		port,
	},
	externals: {
		...externals,
	},
} ) );
