(function () {
	"use strict";

	var storageKey = "spamfox-theme";
	var root = document.documentElement;

	function readTheme() {
		try {
			var stored = window.localStorage.getItem(storageKey);
			return stored === "dark" || stored === "light" ? stored : "light";
		} catch (error) {
			return "light";
		}
	}

	function updateButtons() {
		var dark = root.getAttribute("data-theme") === "dark";
		var english = /^en/i.test(root.lang || "");
		var label = dark
			? (english ? "Light theme" : "Tema claro")
			: (english ? "Dark theme" : "Tema escuro");
		Array.prototype.forEach.call(
			document.querySelectorAll("[data-theme-toggle]"),
			function (button) {
				var icon = button.querySelector("[data-theme-icon]");
				var text = button.querySelector("[data-theme-label]");
				button.setAttribute("aria-label", label);
				button.setAttribute("aria-pressed", dark ? "true" : "false");
				button.title = label;
				if (icon) {
					icon.textContent = dark ? "☀" : "☾";
				}
				if (text) {
					text.textContent = label;
				}
			}
		);
	}

	function applyTheme(theme, persist) {
		var selected = theme === "dark" ? "dark" : "light";
		root.setAttribute("data-theme", selected);
		if (persist) {
			try {
				window.localStorage.setItem(storageKey, selected);
			} catch (error) {
				// Keep the current page usable when browser storage is unavailable.
			}
		}
		updateButtons();
	}

	applyTheme(readTheme(), false);

	function bindToggleButtons() {
		updateButtons();
		Array.prototype.forEach.call(
			document.querySelectorAll("[data-theme-toggle]"),
			function (button) {
				button.addEventListener("click", function () {
					applyTheme(
						root.getAttribute("data-theme") === "dark" ? "light" : "dark",
						true
					);
				});
			}
		);
	}

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", bindToggleButtons);
	} else {
		bindToggleButtons();
	}

	window.addEventListener("storage", function (event) {
		if (event.key === storageKey) {
			applyTheme(event.newValue, false);
		}
	});
})();
