<script lang="ts">
import type { Snippet } from "svelte";

let {
	open = false,
	// biome-ignore lint/correctness/noUnusedVariables: used in template
	title = "",
	// biome-ignore lint/correctness/noUnusedVariables: used in template
	width = "420px",
	onClose,
	// biome-ignore lint/correctness/noUnusedVariables: used in template
	children,
}: {
	open?: boolean;
	title?: string;
	width?: string;
	onClose?: () => void;
	children?: Snippet;
} = $props();

let dialogElement: HTMLDivElement | undefined = $state();

// biome-ignore lint/correctness/noUnusedVariables: used in template
function handleKeydown(event: KeyboardEvent) {
	if (!open) return;

	if (event.key === "Escape") {
		onClose?.();
		return;
	}

	// Focus trap
	if (event.key === "Tab" && dialogElement) {
		const focusableElements = dialogElement.querySelectorAll<HTMLElement>(
			'a[href], button, textarea, input[type="text"], input[type="radio"], input[type="checkbox"], select, [tabindex]:not([tabindex="-1"])',
		);

		if (focusableElements.length === 0) {
			event.preventDefault();
			return;
		}

		const firstElement = focusableElements[0];
		const lastElement = focusableElements[focusableElements.length - 1];

		if (event.shiftKey) {
			if (document.activeElement === firstElement) {
				lastElement.focus();
				event.preventDefault();
			}
		} else {
			if (document.activeElement === lastElement) {
				firstElement.focus();
				event.preventDefault();
			}
		}
	}
}

$effect(() => {
	if (open && dialogElement) {
		// Focus the dialog or first focusable element when opened
		const focusableElements = dialogElement.querySelectorAll<HTMLElement>(
			'a[href], button, textarea, input[type="text"], input[type="radio"], input[type="checkbox"], select, [tabindex]:not([tabindex="-1"])',
		);
		if (focusableElements.length > 0) {
			focusableElements[0].focus();
		} else {
			dialogElement.focus();
		}
	}
});
</script>

<svelte:window onkeydown={handleKeydown} />

{#if open}
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div class="modal-backdrop" onclick={() => onClose?.()}>
		<div
			bind:this={dialogElement}
			class="modal-dialog"
			role="dialog"
			aria-modal="true"
			aria-label={title || "Dialog"}
			style="max-width: {width};"
			onclick={(e) => e.stopPropagation()}
			tabindex="-1"
		>
			{#if title}
				<div class="modal-title">{title}</div>
			{/if}
			<div class="modal-content">
				{@render children?.()}
			</div>
		</div>
	</div>
{/if}

<style>
	.modal-backdrop {
		position: fixed;
		top: 0;
		left: 0;
		width: 100vw;
		height: 100vh;
		background: rgba(0, 0, 0, 0.45);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 9100;
		padding: 16px;
		box-sizing: border-box;
	}

	.modal-dialog {
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: 12px;
		box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
		padding: 28px 28px 24px;
		width: 100%;
		max-height: calc(100vh - 32px);
		overflow-y: auto;
		animation: modal-in 0.2s cubic-bezier(0.16, 1, 0.3, 1);
		box-sizing: border-box;
		outline: none;
	}

	.modal-title {
		font-size: 15px;
		font-weight: 700;
		color: var(--text);
		letter-spacing: -0.02em;
		margin-bottom: 16px;
	}

	.modal-content {
		color: var(--text);
	}

	@keyframes modal-in {
		from {
			opacity: 0;
			transform: translateY(8px) scale(0.98);
		}
		to {
			opacity: 1;
			transform: translateY(0) scale(1);
		}
	}
</style>
