import '../scss/admin.scss';

(function () {
	'use strict';

	function byId(id) {
		return document.getElementById(id);
	}

	function appendLog(boxId, text, reset) {
		var box = byId(boxId);
		if (!box) {
			return;
		}
		if (reset) {
			box.value = '';
		}
		var now = new Date().toISOString();
		box.value += '[' + now + ']\n' + text + '\n\n';
		box.scrollTop = box.scrollHeight;
	}

	function startSpinner(boxId, label) {
		var box = byId(boxId);
		if (!box) {
			return function () {};
		}

		var frames = ['|', '/', '-', '\\'];
		var idx = 0;
		box.value = '[' + new Date().toISOString() + ']\n' + label + ': started\n' + label + ': working ' + frames[idx];
		box.scrollTop = box.scrollHeight;

		var intervalId = window.setInterval(function () {
			idx = (idx + 1) % frames.length;
			var lines = box.value.split('\n');
			if (lines.length >= 3) {
				lines[lines.length - 1] = label + ': working ' + frames[idx];
				box.value = lines.join('\n');
				box.scrollTop = box.scrollHeight;
			}
		}, 140);

		return function stopSpinner() {
			window.clearInterval(intervalId);
		};
	}

	function setButtonsDisabled(disabled) {
		var quickBtn = byId('sc-test-ldap-quick');
		var ldapBtn = byId('sc-test-ldap-auth');
		var ssoBtn = byId('sc-test-sso');
		if (quickBtn) {
			quickBtn.disabled = disabled;
		}
		if (ldapBtn) {
			ldapBtn.disabled = disabled;
		}
		if (ssoBtn) {
			ssoBtn.disabled = disabled;
		}
	}

	function runTest(action, nonce, label, boxId, mode) {
		var username = byId('sc_test_username') ? byId('sc_test_username').value : '';
		var password = byId('sc_test_password') ? byId('sc_test_password').value : '';
		appendLog(boxId, '', true);
		setButtonsDisabled(true);
		var stopSpinner = startSpinner(boxId, label);

		var data = new URLSearchParams();
		data.append('action', action);
		data.append('_ajax_nonce', nonce);
		data.append('username', username);
		data.append('password', password);
		data.append('mode', mode || 'auth');

		fetch(signclaveSsoAdmin.ajaxUrl, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: data.toString()
		})
			.then(function (r) {
				return r.text().then(function (text) {
					try {
						return JSON.parse(text);
					} catch (e) {
						return {
							success: false,
							data: {
								log: label + ': server returned non-JSON response.\n\n' + text
							}
						};
					}
				});
			})
			.then(function (payload) {
				stopSpinner();
				setButtonsDisabled(false);
				if (payload && payload.data && payload.data.log) {
					appendLog(boxId, payload.data.log, true);
				} else {
					appendLog(boxId, JSON.stringify(payload || {}, null, 2), true);
				}
			})
			.catch(function (err) {
				stopSpinner();
				setButtonsDisabled(false);
				appendLog(boxId, label + ': failed: ' + err.message, false);
			});
	}

	function wireUserFilterByDirectoryType() {
		var dirSelect = document.querySelector('select[name="signclave_sso_options[ldap][directory_type]"]');
		var filterInput = byId('sc-user-filter');
		var helper = byId('sc-user-filter-help');
		if (!dirSelect || !filterInput || !helper) {
			return;
		}

		var defaults = {
			edir: '(&(objectClass=inetOrgPerson)(cn=%s))',
			ad: '(&(objectClass=user)(sAMAccountName=%s))'
		};

		function renderHelp(type) {
			if (type === 'ad') {
				helper.innerHTML = 'Use <code>%s</code> as username placeholder. Typical AD filter: <code>(&amp;(objectClass=user)(sAMAccountName=%s))</code>.';
				filterInput.placeholder = defaults.ad;
			} else {
				helper.innerHTML = 'Use <code>%s</code> as username placeholder. Typical eDirectory filter: <code>(&amp;(objectClass=inetOrgPerson)(cn=%s))</code>.';
				filterInput.placeholder = defaults.edir;
			}
		}

		renderHelp(dirSelect.value);
		dirSelect.addEventListener('change', function () {
			var current = (filterInput.value || '').trim();
			if (!current || current === defaults.edir || current === defaults.ad) {
				filterInput.value = defaults[dirSelect.value] || defaults.edir;
			}
			renderHelp(dirSelect.value);
		});
	}

	function wireCopyMetadata() {
		var copyBtn = byId('sc-copy-metadata');
		var preview = byId('sc-metadata-preview');
		if (!copyBtn || !preview) {
			return;
		}

		copyBtn.addEventListener('click', function () {
			var text = preview.value || '';
			if (!text) {
				return;
			}

			function markCopied() {
				var original = copyBtn.textContent;
				copyBtn.textContent = (window.signclaveSsoAdmin && signclaveSsoAdmin.copied) ? signclaveSsoAdmin.copied : 'Copied';
				window.setTimeout(function () {
					copyBtn.textContent = original;
				}, 1500);
			}

			if (navigator.clipboard && navigator.clipboard.writeText) {
				navigator.clipboard.writeText(text).then(markCopied).catch(function () {
					preview.focus();
					preview.select();
					document.execCommand('copy');
					markCopied();
				});
				return;
			}

			preview.focus();
			preview.select();
			document.execCommand('copy');
			markCopied();
		});
	}

	document.addEventListener('DOMContentLoaded', function () {
		var quickBtn = byId('sc-test-ldap-quick');
		var ldapBtn = byId('sc-test-ldap-auth');
		var ssoBtn = byId('sc-test-sso');

		if (quickBtn) {
			quickBtn.addEventListener('click', function () {
				runTest('signclave_sso_test_ldap', signclaveSsoAdmin.ldapNonce, 'LDAP quick test', 'sc-ldap-quick-log', 'quick');
			});
		}

		if (ldapBtn) {
			ldapBtn.addEventListener('click', function () {
				runTest('signclave_sso_test_ldap', signclaveSsoAdmin.ldapNonce, 'LDAP auth test', 'sc-tech-log', 'auth');
			});
		}

		if (ssoBtn) {
			ssoBtn.addEventListener('click', function () {
				runTest('signclave_sso_test_sso', signclaveSsoAdmin.ssoNonce, 'SSO test', 'sc-tech-log', 'auth');
			});
		}

		wireUserFilterByDirectoryType();
		wireCopyMetadata();
	});
})();
