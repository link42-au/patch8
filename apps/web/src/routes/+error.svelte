<script>
import { base } from "$app/paths";
import { page } from "$app/state";
</script>

<div class="error-state">
  <div class="error-state-icon">&#9670;</div>
  <div class="error-state-title">{page.status}</div>
  <p class="error-state-msg">{page.error?.message || "Something went wrong"}</p>
  <a href="{base}/" class="error-state-link">Back to home</a>
</div>
