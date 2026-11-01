<?php
/**
 * Plugin Name: Fixture attack surface
 * Synthetic fixture for wp-plugin-audit tests. Not derived from any real plugin.
 */

class FX_Admin {
	public function __construct() {
		add_action( 'wp_ajax_fx_a', array( $this, 'ajax_a' ) );
		add_action( 'wp_ajax_nopriv_fx_b', [ $this, 'ajax_b' ] );
		add_action( 'admin_post_nopriv_fx_c', 'fx_post_c' );
		add_action( 'admin_post_fx_d', array( __CLASS__, 'post_d' ) );
		add_action( 'rest_api_init', array( $this, 'routes' ) );
		add_shortcode( 'fx_sc', array( $this, 'shortcode' ) );
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'wp_ajax_fx_closure', function () {
			check_ajax_referer( 'fx_closure' );
			echo esc_html( $_POST['m'] );
		} );
	}

	private function verify() {
		check_ajax_referer( 'fx_a' );
		return current_user_can( 'edit_posts' );
	}

	public function ajax_a() {
		if ( ! $this->verify() ) {
			wp_die();
		}
		update_option( 'fx_a', sanitize_text_field( $_POST['a'] ) );
	}

	public function ajax_b() {
		update_option( 'fx_b', $_POST['b'] );
	}

	public static function post_d() {
		check_admin_referer( 'fx_d' );
		if ( current_user_can( 'manage_options' ) ) {
			update_option( 'fx_d', 1 );
		}
	}

	public function routes() {
		register_rest_route( 'fx/v1', '/open', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'rest_open' ),
			'permission_callback' => '__return_true',
		) );
		register_rest_route( 'fx/v1', '/missing', array(
			'methods'  => 'POST',
			'callback' => 'fx_rest_missing',
		) );
		register_rest_route( 'fx/v1', '/guarded', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'rest_guarded' ),
			'permission_callback' => function () {
				return current_user_can( 'manage_options' );
			},
		) );
	}

	public function rest_open( $request ) {
		return rest_ensure_response( $request->get_param( 'q' ) );
	}

	public function rest_guarded( $request ) {
		return rest_ensure_response( 'ok' );
	}

	public function shortcode( $atts ) {
		return '<div>' . esc_html( $atts['t'] ) . '</div>';
	}

	public function menu() {
		add_menu_page( 'FX', 'FX', 'manage_options', 'fx-main', array( $this, 'page_main' ) );
		add_submenu_page( 'fx-main', 'Sub', 'Sub', 'edit_posts', 'fx-sub', array( $this, 'page_sub' ) );
	}

	public function page_main() {
		echo '<h1>FX</h1>';
	}

	public function page_sub() {
		echo '<h1>Sub</h1>';
	}
}

class FX_Widget extends WP_Widget {
	public function widget( $args, $instance ) {
		echo esc_html( $instance['title'] );
	}
}

function fx_post_c() {
	update_option( 'fx_c', $_POST['c'] );
}

function fx_rest_missing( $request ) {
	return rest_ensure_response( 'missing' );
}

function fx_init_reads_get() {
	if ( isset( $_GET['fx_export'] ) ) {
		wp_send_json( array( 'export' => 1 ) );
	}
}

function fx_init_plain() {
	do_action( 'fx_ready' );
}

function fx_cron() {
	update_option( 'fx_last_run', time() );
}

function fx_block_render( $attrs ) {
	return '<p>' . esc_html( $attrs['text'] ) . '</p>';
}

function fx_xmlrpc( $methods ) {
	$methods['fx.hello'] = 'fx_xmlrpc_hello';
	return $methods;
}

function fx_xmlrpc_hello( $args ) {
	return 'hello';
}

new FX_Admin();
add_action( 'init', 'fx_init_reads_get' );
add_action( 'init', 'fx_init_plain' );
add_action( 'fx_cron_task', 'fx_cron' );
wp_schedule_event( time(), 'hourly', 'fx_cron_task' );
register_widget( 'FX_Widget' );
register_block_type( 'fx/block', array( 'render_callback' => 'fx_block_render' ) );
add_filter( 'xmlrpc_methods', 'fx_xmlrpc' );
