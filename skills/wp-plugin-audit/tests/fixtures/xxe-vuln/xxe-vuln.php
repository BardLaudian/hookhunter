<?php
/** Plugin Name: Fixture XXE (vulnerable) */
/** Synthetic fixture for wp-plugin-audit tests. Not derived from any real plugin. */
add_action( 'wp_ajax_nopriv_fx_xml', 'fx_xml' );

function fx_xml() {
	$xml = simplexml_load_string( $_POST['x'], 'SimpleXMLElement', LIBXML_NOENT ); // VULN
	$dom = new DOMDocument();
	$dom->loadXML( $_POST['y'], LIBXML_NOENT | LIBXML_DTDLOAD ); // VULN
	wp_send_json( (string) $xml );
}
