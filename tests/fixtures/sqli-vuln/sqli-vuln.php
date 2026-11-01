<?php
/** Plugin Name: Fixture SQLi (vulnerable) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'wp_ajax_nopriv_fx_find', 'fx_find' );

function fx_find() {
	global $wpdb;
	$id   = wp_unslash( $_GET['id'] );
	$rows = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}fx WHERE id = $id" ); // VULN
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}fx WHERE name = '$id'" ) ); // VULN
	wp_send_json( $rows );
}
