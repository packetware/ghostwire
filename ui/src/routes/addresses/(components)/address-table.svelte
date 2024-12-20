<script lang="ts">
	import * as Table from '$lib/components/ui/table';

	import Actions from './address-actions.svelte';

	let { addresses } = $props();
</script>

<div class="rounded border">
	<Table.Root>
		<Table.Header>
			<Table.Row>
				<Table.Head class="w-[100px]">Address</Table.Head>
				<Table.Head>Version</Table.Head>
				<Table.Head>Location</Table.Head>
				<Table.Head>Default</Table.Head>
				<Table.Head>Firewall</Table.Head>
				<Table.Head class="text-right">Actions</Table.Head>
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each addresses as address}
				<Table.Row>
					<Table.Cell class="font-medium">{address.id}</Table.Cell>
					<Table.Cell>{address.version}</Table.Cell>
					<Table.Cell>{address.location.id}</Table.Cell>
					<Table.Cell>{address.default}</Table.Cell>
					<Table.Cell
						>{#if address.firewall}{address.firewall.name}{:else}N/A{/if}</Table.Cell
					>
					<Table.Cell class="text-right"
						><Actions {address}></Actions></Table.Cell
					>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
</div>
