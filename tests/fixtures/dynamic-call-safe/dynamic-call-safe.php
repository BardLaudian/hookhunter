<?php
/** Plugin Name: Fixture dynamic dispatch (safe twin) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'wp_ajax_nopriv_fx_dyn', 'fx_dyn' );

function fx_dyn() {
	$handlers = array( 'resize' => 'fx_resize', 'crop' => 'fx_crop' );
	$fn       = $handlers[ $_POST['op'] ?? '' ] ?? null;
	if ( $fn ) {
		$fn( absint( $_POST['n'] ) ); // SAFE
	}
	$cb = function ( $x ) {
		return $x * 2;
	};
	$cb( 2 ); // SAFE
	array_map( 'trim', explode( ',', $_POST['list'] ) ); // SAFE
	if ( in_array( $_POST['hook'], array( 'a', 'b' ), true ) ) {
		do_action( 'fx_' . $_POST['hook'] ); // SAFE
	}
	$out = do_shortcode( '[fx_known]' ); // SAFE
	mail( 'a@example.test', 's', 'm', '', 'noreply@example.test' ); // SAFE
	wp_send_json( $out );
}
