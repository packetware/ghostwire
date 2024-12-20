import prisma, { Version, Action } from "$lib/server/db";

export async function CreateAddress(value: string, version: Version, netmask: string, locationId: string) {
  try {
    const address = await prisma.address.create({
      data: {
        id: value,
        version,
        netmask,
        location: {
          connect: { id: locationId },  // Connects the location to the address by ID
        },
        default: Action.ALLOW,  // Default action for the address
      },
    });
    return address;  // Return the created address
  } catch (error) {
    console.error("Error creating address:", error);
    throw new Error("Failed to create address");
  }
}
export async function GetAddress(id: string) {
  try {
    const address = await prisma.address.findUnique({
      where: { id },  // Find the address by ID
      include: {
        location: true,  // You can include related data if needed
        firewall: true,
      },
    });
    return address;
  } catch (error) {
    console.error("Error retrieving address:", error);
    throw new Error("Failed to get address");
  }
}

export async function ListAddress(limit: number, offset: number) {
  try {
    const addresses = await prisma.address.findMany({
      take: limit,  // Limit the number of results
      skip: offset,  // Skip the first 'offset' records
      include: {
        location: true,  // Include related location data
        firewall: true,  // Include related firewall data if necessary
      },
    });
    return addresses;
  } catch (error) {
    console.error("Error listing addresses:", error);
    throw new Error("Failed to list addresses");
  }
}

export async function DeleteAddress(id: string) {
  try {
    const address = await prisma.address.delete({
      where: { id },  // Specify the ID of the address to delete
    });
    return address;
  } catch (error) {
    console.error("Error deleting address:", error);
    throw new Error("Failed to delete address");
  }
}

export async function AddFirewall(addressId: string, firewallId: number) {
  try {
    const updatedAddress = await prisma.address.update({
      where: { id: addressId },  // Find the address by ID
      data: {
        firewall: {
          connect: { id: firewallId },  // Connect the firewall by its ID
        },
      },
    });
    return updatedAddress;
  } catch (error) {
    console.error("Error adding firewall:", error);
    throw new Error("Failed to add firewall to address");
  }
}