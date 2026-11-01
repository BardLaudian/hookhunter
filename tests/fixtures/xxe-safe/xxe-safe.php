<?php
/** Plugin Name: Fixture XXE (safe twin) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'wp_ajax_nopriv_fx_xml', 'fx_xml' );

function fx_xml() {
	$xml = simplexml_load_string( $_POST['x'] ); // SAFE
	$dom = new DOMDocument();
	$dom->loadXML( $_POST['y'] ); // SAFE
	wp_send_json( (string) $xml );
}
