<script lang="ts">
	import {
		Home,
		Ghost,
		Network,
		BrickWall,
		EthernetPort,
		Settings,
		Ban,
		MapPin,
		ChevronDown
	} from 'lucide-svelte';
	import * as Sidebar from '$lib/components/ui/sidebar';
	import * as Collapsible from '$lib/components/ui/collapsible';
	import LightSwitch from './light-switch.svelte';

	// Menu items.
	const items = [
    {
			title: 'Home',
			url: '/',
			icon: Home
		},
		{
			title: 'Addresses',
			url: '/addresses',
			icon: Network
		},
		{
			title: 'Firewalls',
			url: '/firewalls',
			icon: BrickWall
		},
		{
			title: 'Nodes',
			url: '/nodes',
			icon: EthernetPort
		},
    {
			title: 'Locations',
			url: '/locations',
			icon: MapPin
		},
		{
			title: 'Block List',
			url: '/blocklist',
			icon: Ban
		}
	];
</script>

<Sidebar.Root>
	<Sidebar.Header>
		<h3 class="flex items-center font-bold"><Ghost class="mr-2"></Ghost>Ghostwire</h3>
	</Sidebar.Header>
	<Sidebar.Content>
		<Sidebar.Group>
			<Sidebar.GroupContent>
				<Sidebar.Menu>
					{#each items as item (item.title)}
						<Sidebar.MenuItem>
							<Sidebar.MenuButton>
								{#snippet child({ props })}
									<a href={item.url} {...props}>
										<item.icon />
										<span>{item.title}</span>
									</a>
								{/snippet}
							</Sidebar.MenuButton>
						</Sidebar.MenuItem>
					{/each}
				</Sidebar.Menu>
			</Sidebar.GroupContent>
		</Sidebar.Group>
	</Sidebar.Content>
	<Sidebar.Footer>
		<LightSwitch></LightSwitch>
	</Sidebar.Footer>
</Sidebar.Root>
