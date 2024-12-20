import { fail } from '@sveltejs/kit';
import type { PageServerLoad, Actions } from './$types';
import { ListAddress, CreateAddress } from '$lib/server/helpers/addresses';
import { ListLocations } from '$lib/server/helpers/locations';
import { Version } from "$lib/server/db"
import { ValidIPv4, ValidIPv6 } from '$lib/helpers/internet';

export const load: PageServerLoad = async ({ url }) => {
  const limit = url.searchParams.get('limit') ? Number(url.searchParams.get('limit')) : 20;
  const offset = url.searchParams.get('offset') ? Number(url.searchParams.get('offset')) : 0;

  return {
    locations: await ListLocations(),
    addresses: await ListAddress(limit, offset),
  };
};

export const actions = {
  new: async ({ request }) => {
    const data = await request.formData();
    const location = String(data.get('location'));
    const versionString = String(data.get('version'));
    const address = String(data.get('address'));
    const netmask = String(data.get('netmask'));

    if (!address || (!ValidIPv4(address) && !ValidIPv6(address))) {
      return fail(400, { message: "Invalid address" });
    }

    const version = Version[versionString as keyof typeof Version];

    const newAddress = await CreateAddress(address, version, netmask, location)

    return {
      success: true,
      address: newAddress
    }
  }
} satisfies Actions;