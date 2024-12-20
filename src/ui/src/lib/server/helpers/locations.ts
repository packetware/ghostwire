import prisma from "$lib/server/db";

export async function ListLocations() {
  try {
    const locations = await prisma.location.findMany();
    return locations;
  } catch (error) {
    console.error("Error listing locations:", error);
    throw new Error("Failed to list locations");
  }
}