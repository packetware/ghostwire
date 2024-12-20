<script lang="ts">
	import { flip } from 'svelte/animate';

	import * as Table from '$lib/components/ui/table';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import * as Select from '$lib/components/ui/select';

	import { ArrowUp, ArrowDown } from 'lucide-svelte';

	let { rules = $bindable() } = $props();

	let editId = $state();

	const moveRule = (index: number, direction: 'up' | 'down') => {
		if (
			(direction === 'up' && index === 0) ||
			(direction === 'down' && index === rules.length - 1)
		) {
			return; // Can't move further in this direction
		}

		const newRules = [...rules];
		const newIndex = direction === 'up' ? index - 1 : index + 1;
		const [removedRule] = newRules.splice(index, 1);
		newRules.splice(newIndex, 0, removedRule);
		rules = [...newRules];
	};

	$inspect(rules);
</script>

<Table.Root>
	<Table.Header>
		<Table.Row>
			<Table.Head class="w-[40px]">Priority</Table.Head>
			<Table.Head>Name</Table.Head>
			<Table.Head>Source IP</Table.Head>
			<Table.Head>Protocol</Table.Head>
			<Table.Head>Destination Port</Table.Head>
			<Table.Head>Action</Table.Head>
			<Table.Head class="text-right">Adjust Priority</Table.Head>
			<Table.Head class="text-right">Edit</Table.Head>
		</Table.Row>
	</Table.Header>
	<Table.Body>
		{#each rules as rule, i (rule.id)}
			<tr
				class="hover:bg-muted/50 data-[state=selected]:bg-muted border-b transition-colors"
				animate:flip={{ duration: 300 }}
			>
				{#if editId === rule.id}
					<Table.Cell class="font-medium">{i + 1}</Table.Cell>
					<Table.Cell><Input bind:value={rule.name}></Input></Table.Cell>
					<Table.Cell><Input bind:value={rule.src_ip}></Input></Table.Cell>
					<Table.Cell
						><Select.Root type="single" bind:value={rule.protocol}>
							<Select.Trigger>{rule.protocol}</Select.Trigger>
							<Select.Content>
								<Select.Item value="TCP">TCP</Select.Item>
								<Select.Item value="UDP">UDP</Select.Item>
								<Select.Item value="ICMP">ICMP</Select.Item>
							</Select.Content>
						</Select.Root></Table.Cell
					>
					<Table.Cell><Input bind:value={rule.port}></Input></Table.Cell>
					<Table.Cell
						><Select.Root type="single" bind:value={rule.action}>
							<Select.Trigger>{rule.action}</Select.Trigger>
							<Select.Content>
								<Select.Item value="ALLOW">ALLOW</Select.Item>
								<Select.Item value="BLOCK">BLOCK</Select.Item>
							</Select.Content>
						</Select.Root></Table.Cell
					>
					<Table.Cell class="text-right">
						<div class="flex justify-end space-x-2">
							<Button
								variant="outline"
								size="icon"
								onclick={() => moveRule(i, 'up')}
								disabled={i === 0}
								aria-label={`Move ${rule.name} up`}
							>
								<ArrowUp class="h-4 w-4" />
							</Button>
							<Button
								variant="outline"
								size="icon"
								onclick={() => moveRule(i, 'down')}
								disabled={i === rules.length - 1}
								aria-label={`Move ${rule.name} down`}
							>
								<ArrowDown class="h-4 w-4" />
							</Button>
						</div>
					</Table.Cell>
					<Table.Cell class="text-right">
						<Button variant="outline" size="sm" onclick={() => (editId = undefined)}>Done</Button>
					</Table.Cell>
				{:else}
					<Table.Cell class="font-medium">{i + 1}</Table.Cell>
					<Table.Cell>{rule.name}</Table.Cell>
					<Table.Cell>{rule.src_ip}</Table.Cell>
					<Table.Cell>{rule.protocol}</Table.Cell>
					<Table.Cell>{rule.port}</Table.Cell>
					<Table.Cell>{rule.action}</Table.Cell>
					<Table.Cell class="text-right">
						<div class="flex justify-end space-x-2">
							<Button
								variant="outline"
								size="icon"
								onclick={() => moveRule(i, 'up')}
								disabled={i === 0}
								aria-label={`Move ${rule.name} up`}
							>
								<ArrowUp class="h-4 w-4" />
							</Button>
							<Button
								variant="outline"
								size="icon"
								onclick={() => moveRule(i, 'down')}
								disabled={i === rules.length - 1}
								aria-label={`Move ${rule.name} down`}
							>
								<ArrowDown class="h-4 w-4" />
							</Button>
						</div>
					</Table.Cell>
					<Table.Cell class="text-right">
						<div class="space-x-2">
							<Button variant="outline" size="sm" onclick={() => (editId = rule.id)}>Edit</Button>
							<Button variant="outline" size="sm" onclick={() => rules.splice(i, 1)}>Delete</Button>
						</div>
					</Table.Cell>
				{/if}
			</tr>
		{/each}
	</Table.Body>
</Table.Root>
