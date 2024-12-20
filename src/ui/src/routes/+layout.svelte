<script lang="ts">
	import '../app.css';
	import { ModeWatcher } from 'mode-watcher';
	import { Toaster } from '$lib/components/ui/sonner';
	import * as Sidebar from '$lib/components/ui/sidebar';
	import AppSidebar from '$lib/components/app-sidebar.svelte';

	let { children } = $props();
</script>

<ModeWatcher />
<Toaster />

<Sidebar.Provider class="w-full">
	<AppSidebar />
	<main class="w-full">
		<div class="absolute">
			<Sidebar.Trigger class="translate-x-2 translate-y-2" />
		</div>
		<div class="m-4">
			{@render children?.()}
		</div>
	</main>
</Sidebar.Provider>
