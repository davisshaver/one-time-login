<?php
/**
 * Plugin Name:     One Time Login Fork
 * Plugin URI:      https://wordpress.org/plugins/one-time-login/
 * Description:     Use WP-CLI to generate a one-time login URL for any user.
 * Author:          Daniel Bachhuber
 * Author URI:      https://danielbachhuber.com
 * Text Domain:     one-time-login
 * Domain Path:     /languages
 * Version:         0.4.0
 *
 * @package         One_Time_Login
 */


/**
 * Enqueue and localize scripts for form handler.
 */
function one_time_login_enqueue() {
	if ( function_exists( 'is_amp_endpoint' ) && is_amp_endpoint() ) {
		return;
	}
	wp_register_script(
		'one-time-login-js',
		plugin_dir_url( __FILE__ ) . 'login.js'
	);
	wp_localize_script(
		'one-time-login-js',
		'oneTimeLogin',
		[
			'ajax_url' => admin_url( 'admin-ajax.php' ),
			'security' => wp_create_nonce( 'one-time-login-nonce' ),
		]
	);
	wp_enqueue_script(
		'one-time-login-js'
	);
}

add_action( 'wp_enqueue_scripts', 'one_time_login_enqueue' );

/**
 * Print custom CSS for one time login.
 */
function one_time_login_wp_head() {
	if ( function_exists( 'is_amp_endpoint' ) && is_amp_endpoint() ) {
		echo '<style>
			.one-time-login-form input { width: 100%; }
		</style>';
	} else {
		echo '<style>
		.one-time-login-form { display: flex; justify-content: space-between; }
		.one-time-login-form label { display: none; }
		</style>';
	}
}
add_action( 'wp_head', 'one_time_login_wp_head' );

/**
 * Print simple form template form one time login.
 */
function one_time_login_form() {
	if ( is_user_logged_in() ) {
		global $wp;
		return apply_filters(
			'one-time-login-logged-in',
			sprintf(
				'<p>%s <a href="%s">%s</a></p>',
				__( 'Already logged in.', 'one-time-login' ),
				esc_url( wp_logout_url( home_url( $wp->request ) ) ),
				__( 'Logout.', 'one-time-login' )
			)
		);
	}
	$input_id = 'one-time-login-form-' . rand();
	if ( function_exists( 'is_amp_endpoint' ) && is_amp_endpoint() ) {
		return sprintf(
			'<form
				name="submit"
				class="one-time-login-form hide-inputs"
				method="post"
				action-xhr="%s"
				target="_top">
				<div class="one-time-login-inputs">
					<input type="email" name="email" placeholder="email@domain.com" required>
					<input name="action" type="hidden" value="send_one_time_login_email">
					<input name="security" type="hidden" value="%s">
					<input type="submit" value="%s">
				</div>
				<div submit-success>
					<template type="amp-mustache">{{data}}</template>
				</div>
			</form>',
			esc_url( admin_url( 'admin-ajax.php' ) ),
			esc_attr( wp_create_nonce( 'one-time-login-nonce' ) ),
			__( 'Send Login Link', 'one-time-login' )
		);
	}
	return sprintf(
		'<form class="one-time-login-form"><div class="one-time-login-response" style="display: none;">%s</div><label for="%s">%s</label><input id="%s" name="email" placeholder="%s" type="email" required /><input type="submit" value="%s" /> </form>',
		esc_html( __( 'If an account exists with that address, a login link has been sent.', 'one-time-login' ) ),
		esc_attr( $input_id ),
		esc_html( __( 'Email', 'one-time-login' ) ),
		esc_attr( $input_id ),
		esc_attr( __( 'Login with your email', 'one-time-login' ) ),
		esc_attr( __( 'Send link', 'one-time-login' ) )
	);
}

add_shortcode( 'one-time-login', 'one_time_login_form' );

/**
 * Admin AJAX endpoint for sending an email.
 */
function callback_send_one_time_login_by_email() {
	if ( ! isset( $_REQUEST['email'] ) ) {
		wp_send_json_error( __( 'Invalid request.', 'one-time-login' ) );
	}
	if ( ! check_ajax_referer( 'one-time-login-nonce', 'security', false ) ) {
		wp_send_json_error( __( 'Invalid security token.', 'one-time-login' ) );
	}
	$email = sanitize_email( wp_unslash( $_REQUEST['email'] ) );
	if ( ! is_email( $email ) ) {
		wp_send_json_error( __( 'Invalid format.', 'one-time-login' ) );
	}
	send_one_time_login_by_email( $email );
	wp_send_json_success( __( 'Login link sent if email is registered.', 'one-time-login' ) );
}

add_action( 'wp_ajax_send_one_time_login_email', 'callback_send_one_time_login_by_email' );
add_action( 'wp_ajax_nopriv_send_one_time_login_email', 'callback_send_one_time_login_by_email' );

/**
 * Send a one time login based on a email.
 *
 * @param string $email Email address for the user.
 */
function send_one_time_login_by_email( $email ) {
	$login_data = one_time_login_by_email( $email, true );
	if ( false === $login_data ) {
		return;
	}
	wp_mail(
		$email,
		apply_filters( 'one_time_login_subject', 'Login', $email, $login_data['user'] ),
		apply_filters( 'one_time_login_message', $login_data['url'], $email, $login_data['user'] )
	);
}

/**
 * Get a one time login based on an email.
 *
 * @param string  $email Email address for the user.
 * @param boolean $delay_delete Delete after 15 mins.
 * @return mixed Login URL.
 */
function one_time_login_by_email( $email, $delay_delete ) {
	if ( ! is_email( $email ) ) {
		return false;
	}
	$user = get_user_by( 'email', $email );
	if ( ! $user ) {
		return false;
	}
	$password = wp_generate_password();
	$token = sha1( $password );
	update_user_meta( $user->ID, 'one_time_login_token', $token );
	if ( $delay_delete ) {
		wp_schedule_single_event( time() + ( 15 * MINUTE_IN_SECONDS ), 'one_time_login_cleanup_expired_tokens', array( $user->ID, [ $token ] ) );
	}
	do_action( 'one_time_login_created', $user );
	$query_args = array(
		'user_id'              => $user->ID,
		'one_time_login_token' => $token,
	);
	$login_url = add_query_arg( $query_args, wp_login_url() );
	return [
		'url'  => $login_url,
		'user' => $user,
	];
}

/**
 * Generate one or multiple one-time login URL(s) for any user.
 *
 * @param WP_User|null $user  ID, email address, or user login for the user.
 * @param int          $count           Generate a specified number of login tokens (default: 1).
 * @param bool         $delay_delete   Delete existing tokens after 15 minutes, instead of immediately.
 *
 * @return array
 */
function one_time_login_generate_tokens( $user, $count, $delay_delete ) {
	$tokens     = $new_tokens = array();
	$login_urls = array();

	if ( $user instanceof WP_User ) {
		if ( $delay_delete ) {
			$tokens = get_user_meta( $user->ID, 'one_time_login_token', true );
			$tokens = is_string( $tokens ) ? array( $tokens ) : $tokens;
			wp_schedule_single_event( time() + ( 15 * MINUTE_IN_SECONDS ), 'one_time_login_cleanup_expired_tokens', array( $user->ID, $tokens ) );
		}

		for ( $i = 0; $i < $count; $i++ ) {
			$password     = wp_generate_password();
			$token        = sha1( $password );
			$tokens[]     = $token;
			$new_tokens[] = $token;
		}

		update_user_meta( $user->ID, 'one_time_login_token', $tokens );
		do_action( 'one_time_login_created', $user );
		foreach ( $new_tokens as $token ) {
			$query_args   = array(
				'user_id'              => $user->ID,
				'one_time_login_token' => $token,
			);
			$login_urls[] = add_query_arg( $query_args, wp_login_url() );
		}
	}

	return $login_urls;
}

/**
 * Generate one-time tokens using WP CLI.
 *
 * ## OPTIONS
 *
 * <user>
 * [--count=<count>]
 * [--delay-delete]
 *
 * ## EXAMPLES
 *
 *     # Generate two one-time login URLs.
 *     $ wp user one-time-login testuser --count=2
 *     http://wpdev.test/wp-login.php?user_id=2&one_time_login_token=ebe62e3
 *     http://wpdev.test/wp-login.php?user_id=2&one_time_login_token=eb41c77
 *
 * @param array $args
 * @param array $assoc_args
 */
function one_time_login_wp_cli_command( $args, $assoc_args ) {
	$fetcher      = new WP_CLI\Fetchers\User();
	$user         = $fetcher->get_check( $args[0] );
	$delay_delete = WP_CLI\Utils\get_flag_value( $assoc_args, 'delay-delete' );
	$count        = (int) ( $assoc_args['count'] ?? 1 );

	$login_urls = one_time_login_generate_tokens( $user, $count, $delay_delete );
	foreach ( $login_urls as $login_url ) {
		WP_CLI::log( $login_url );
	}
}

if ( class_exists( 'WP_CLI' ) ) {
	WP_CLI::add_command( 'user one-time-login', 'one_time_login_wp_cli_command' );
}

/**
 * Generate one-time tokens using WP CLI.
 *
 * ## OPTIONS
 *
 * /count/<count>/
 * /delay-delete/<0 or 1>
 *
 * ## EXAMPLES
 *
 *     # Generate two one-time login URLs.
 *     curl --user "admin:RrcZY8bDQBpT7CYrkYk8e9k7" http://localhost:8889/wp-json/one-time-login/v1/token
 *     http://wpdev.test/wp-login.php?user_id=2&one_time_login_token=ebe62e3
 *     http://wpdev.test/wp-login.php?user_id=2&one_time_login_token=eb41c77
 *
 * @param WP_REST_Request $request
 *
 * @return WP_REST_Response
 */
function one_time_login_api_request( WP_REST_Request $request ) {

	$user         = get_user_by( 'login', $request['user'] );
	$delay_delete = (bool) ( $request['delay_delete'] ?? false );
	$count        = (int) ( $request['count'] ?? 1 );

	$login_urls = one_time_login_generate_tokens( $user, $count, $delay_delete );

	return new WP_REST_Response( $login_urls );
}

/**
 * Registers the API endpoint for generating one-time logins.
 */
function one_time_login_rest_api_init() {
	register_rest_route(
		'one-time-login/v1',
		'/token',
		array(
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => 'one_time_login_api_request',
				'args'                => array(
					'user'         => array(
						'required' => true,
					),
					'count'        => array(
						'required'          => false,
						'validate_callback' => function ( $param ) {
							return is_numeric( $param );
						},
					),
					'delay_delete' => array(
						'required'          => false,
						'validate_callback' => function ( $param ) {
							return is_numeric( $param );
						},
					),
				),
				'permission_callback' => function ( WP_REST_Request $request ) {
					if ( empty( $request['user'] ) ) {
						return false;
					}
					$user = get_user_by( 'login', $request['user'] );
					return current_user_can( 'edit_user', $user->ID );
				},
			),
		)
	);
}

add_action( 'rest_api_init', 'one_time_login_rest_api_init' );

/**
 * Handle cleanup process for expired one-time login tokens.
 *
 * @param int   $user_id
 * @param array $expired_tokens
 */
function one_time_login_cleanup_expired_tokens( $user_id, $expired_tokens ) {
	$tokens     = get_user_meta( $user_id, 'one_time_login_token', true );
	$tokens     = is_string( $tokens ) ? array( $tokens ) : $tokens;
	$new_tokens = array();
	foreach ( $tokens as $token ) {
		if ( ! in_array( $token, $expired_tokens, true ) ) {
			$new_tokens[] = $token;
		}
	}
	update_user_meta( $user_id, 'one_time_login_token', $new_tokens );
}

add_action( 'one_time_login_cleanup_expired_tokens', 'one_time_login_cleanup_expired_tokens', 10, 2 );

/**
 * Log a request in as a user if the token is valid.
 */
function one_time_login_handle_token() {
	global $pagenow;

	if ( 'wp-login.php' !== $pagenow || empty( $_GET['user_id'] ) || empty( $_GET['one_time_login_token'] ) ) {
		return;
	}

	if ( is_user_logged_in() ) {
		$error = sprintf( __( 'Invalid one-time login token, but you are logged in as \'%1$s\'. <a href="%2$s">Go to the dashboard instead</a>?', 'one-time-login' ), wp_get_current_user()->user_login, admin_url() );
	} else {
		$error = sprintf( __( 'Invalid one-time login token. <a href="%s">Try signing in instead</a>?', 'one-time-login' ), wp_login_url() );
	}

	// Ensure any expired crons are run
	// It would be nice if WP-Cron had an API for this, but alas.
	$crons = _get_cron_array();
	if ( ! empty( $crons ) ) {
		foreach ( $crons as $time => $hooks ) {
			if ( time() < $time ) {
				continue;
			}
			foreach ( $hooks as $hook => $hook_events ) {
				if ( 'one_time_login_cleanup_expired_tokens' !== $hook ) {
					continue;
				}
				foreach ( $hook_events as $data ) {
					if ( ! defined( 'DOING_CRON' ) ) {
						define( 'DOING_CRON', true );
					}
					do_action_ref_array( $hook, $data['args'] );
					wp_unschedule_event( $time, $hook, $data['args'] );
				}
			}
		}
	}

	// Use a generic error message to ensure user ids can't be sniffed.
	$user = get_user_by( 'id', (int) $_GET['user_id'] );
	if ( ! $user ) {
		wp_die( $error );
	}

	$tokens   = get_user_meta( $user->ID, 'one_time_login_token', true );
	$tokens   = is_string( $tokens ) ? array( $tokens ) : $tokens;
	$is_valid = false;
	foreach ( $tokens as $i => $token ) {
		if ( hash_equals( $token, $_GET['one_time_login_token'] ) ) {
			$is_valid = true;
			unset( $tokens[ $i ] );
			break;
		}
	}

	if ( ! $is_valid ) {
		wp_die( $error );
	}

	do_action( 'one_time_login_logged_in', $user );
	update_user_meta( $user->ID, 'one_time_login_token', $tokens );
	wp_set_auth_cookie( $user->ID, true, is_ssl() );
	do_action( 'one_time_login_after_auth_cookie_set', $user );

	if ( isset( $_GET['redirect_to'] ) ) {
		one_time_login_safe_redirect( $_GET['redirect_to'] );
	} else {
		one_time_login_safe_redirect( admin_url() );
	}
}

add_action( 'init', 'one_time_login_handle_token' );

/**
 * Redirect to a URL, and only exit if we're not running tests.
 *
 * @param string $location
 * @param int    $status
 * @param string $x_redirect_by
 */
function one_time_login_safe_redirect( $location, $status = 302, $x_redirect_by = 'WordPress' ) {
	wp_safe_redirect( $location, $status, $x_redirect_by );
	if ( ! defined( 'ONE_TIME_LOGIN_RUNNING_TESTS' ) || ! ONE_TIME_LOGIN_RUNNING_TESTS ) {
		exit;
	}
}
