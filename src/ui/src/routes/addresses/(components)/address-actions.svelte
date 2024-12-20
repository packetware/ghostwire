<script lang="ts">
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu';
	import { Button } from '$lib/components/ui/button';

	import { Settings2 } from 'lucide-svelte';
	import DropdownMenuSeparator from '$lib/components/ui/dropdown-menu/dropdown-menu-separator.svelte';

	let { address } = $props();
</script>

<DropdownMenu.Root>
	<DropdownMenu.Trigger
		><Button href="addresses/{address.id}" variant="ghost" size="sm"
			><Settings2 class="h-4 w-4"></Settings2></Button
		></DropdownMenu.Trigger
	>
	<DropdownMenu.Content>
		<DropdownMenu.Group>
			<DropdownMenu.Item>Firewall</DropdownMenu.Item>
			<DropdownMenu.Item>Default</DropdownMenu.Item>
			<DropdownMenu.Item>Location</DropdownMenu.Item>
			<DropdownMenu.Separator></DropdownMenu.Separator>
			<DropdownMenu.Item class="bg-destructive">Delete</DropdownMenu.Item>
		</DropdownMenu.Group>
	</DropdownMenu.Content>
</DropdownMenu.Root>
