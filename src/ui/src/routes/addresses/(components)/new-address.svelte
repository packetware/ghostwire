<script>
	import * as Dialog from '$lib/components/ui/dialog';
	import { Button } from '$lib/components/ui/button';
	import * as Select from '$lib/components/ui/select';
	import { Label } from '$lib/components/ui/label';
	import Input from '$lib/components/ui/input/input.svelte';
	import Switch from '$lib/components/ui/switch/switch.svelte';

	import { IPv4CIDRs, IPv6CIDRs } from '$lib/helpers/internet';

	let { locations } = $props();

	const locationItems = locations.map((location) => ({ label: location.id, value: location.id }));

	const versionItems = [
		{
			label: 'IPv4',
			value: 'IPv4'
		},
		{
			label: 'IPv6',
			value: 'IPv6'
		}
	];

	let location = $state(locations[0].id);
	let version = $state('IPv4');
	let netmask = $state(IPv4CIDRs[32].value);

  function versionChange() {
    if (version === "IPv4") {
      netmask = IPv4CIDRs[32].value;
    } else if (version === "IPv6") {
      netmask = IPv6CIDRs[128].value;
    }
  }
</script>

<Dialog.Root>
	<Dialog.Trigger><Button>Add New</Button></Dialog.Trigger>
	<Dialog.Content>
		<form method="POST" action="?/new" class="space-y-4">
			<Dialog.Header>
				<Dialog.Title>Add Additional Addresses</Dialog.Title>
				<Dialog.Description>
					Add a single address or a range and select a location and it will add the addresses to
					ghostwire.
				</Dialog.Description>
			</Dialog.Header>
			<div class="space-y-4">
				<div>
					<Label for="location">Location</Label>
					<Select.Root type="single" name="location" bind:value={location}>
						<Select.Trigger>{location}</Select.Trigger>
						<Select.Content>
							{#each locationItems as item}
								<Select.Item value={item.value}>{item.label}</Select.Item>
							{/each}
						</Select.Content>
					</Select.Root>
				</div>
				<div>
					<Label for="version">Version</Label>
					<Select.Root type="single" name="version" bind:value={version} onValueChange={versionChange}>
						<Select.Trigger>{version}</Select.Trigger>
						<Select.Content>
							{#each versionItems as item}
								<Select.Item value={item.value}>{item.label}</Select.Item>
							{/each}
						</Select.Content>
					</Select.Root>
				</div>
				<div>
					<Label for="address">Address</Label>
					<Input type="string" name="address" placeholder="192.168.1.0" required></Input>
				</div>
				<div class="space-y-2">
					<div class="flex items-center space-x-2">
						<Label for="netmask">Netmask</Label>
					</div>
					<Select.Root type="single" name="netmask" bind:value={netmask}>
						<Select.Trigger>{netmask}</Select.Trigger>
						<Select.Content>
							{#snippet items(CIDRs)}
									{#each CIDRs as CIDR}
										<Select.Item value={CIDR.value}>{CIDR.value}</Select.Item>
									{/each}
							{/snippet}
							{#if version === 'IPv4'}
                {@render items(IPv4CIDRs)}
							{:else if version === 'IPv6'}
                {@render items(IPv6CIDRs)}
							{/if}
						</Select.Content>
					</Select.Root>
				</div>
			</div>
			<Dialog.Footer>
				<Button type="submit">Save</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>
