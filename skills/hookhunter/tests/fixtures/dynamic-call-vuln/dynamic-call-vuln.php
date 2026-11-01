<?php
/** Plugin Name: Fixture dynamic dispatch (vulnerable) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'wp_ajax_nopriv_fx_dyn', 'fx_dyn' );

function fx_dyn() {
	$fn = $_POST['f'];
	$fn( $_POST['a'] ); // VULN
	$cls = sanitize_key( $_POST['c'] );
	new $cls( $_POST['a'] ); // VULN
	array_map( $_POST['cb'], array( 1, 2 ) ); // VULN
	do_action( 'fx_' . $_POST['hook'] ); // VULN
	$out = do_shortcode( wp_unslash( $_POST['content'] ) ); // VULN
	parse_str( $_POST['q'] ); // VULN
	mail( 'a@example.test', 's', 'm', '', $_POST['from'] ); // VULN
	wp_send_json( $out );
}
