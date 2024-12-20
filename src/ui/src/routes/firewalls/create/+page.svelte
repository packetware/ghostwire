<script>
	import { Button } from '$lib/components/ui/button';

	import Editor from '$lib/components/firewall-editor.svelte';

	let rules = $state([
		{
      id: Math.random(),
			name: 'SSH',
			src_ip: '0.0.0.0/0',
			protocol: 'TCP',
			port: '22',
			action: 'ALLOW'
		}
	]);

  async function createFirewall() {

  }
</script>

<h1 class="my-4 text-3xl font-bold">Create Rule</h1>
<div class="mb-4 flex items-center justify-end space-x-2">
	<Button
		onclick={() => {
			rules = [
				...rules,
				{
					id: Math.random(),
					name: 'SSH',
					src_ip: '0.0.0.0/0',
					protocol: 'TCP',
					port: '22',
					action: 'ALLOW'
				}
			];
		}}>Add Rule</Button
	>
	<Button onclick={() => createFirewall()}>Save</Button>
</div>
<Editor bind:rules></Editor>
