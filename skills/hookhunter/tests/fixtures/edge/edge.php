<div class="wrap">Don't parse this apostrophe: echo $_GET['html'];</div>
<?php
/**
 * Plugin Name: Fixture parser edge cases
 * Synthetic fixture for hookhunter tests. Not derived from any real plugin.
 */
namespace Fx\Edge;

// add_action( 'wp_ajax_nopriv_in_comment', 'never_registered' );
/* echo $_GET['in_block_comment']; */
# eval( $_POST['hash_comment'] );

$doc = 'add_action( "wp_ajax_nopriv_in_string", "never" ); echo $_GET["x"];';

$help = <<<TXT
echo $_GET['in_heredoc'];
wp_remote_get( $_POST['in_heredoc'] );
TXT;

class Fetcher {
	public function run( $url ) {
		$a = \wp_remote_get( $url ); // QUALIFIED
		return array( $a, $this->helper( $url ) );
	}

	private function helper( $u ) {
		$cb = function ( $x ) {
			return unserialize( $x ); // IN_CLOSURE
		};
		return $cb( $u );
	}
}

\add_action( 'wp_ajax_edge_real', array( new Fetcher(), 'run' ) );

function render_inline() {
	?>
	<p>Hello <?= $_GET['name'] ?></p> <!-- INLINE_ECHO -->
	<?php
	echo $_GET['after_inline']; // AFTER_INLINE
}
