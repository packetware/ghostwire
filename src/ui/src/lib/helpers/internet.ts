export const ValidIPv4 = (address: string): boolean => {
  const ipv4Regex = /^(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})(\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})){3}$/;
  return ipv4Regex.test(address);
};

export const IPv4CIDRs = Array.from({ length: 33 }, (_, i) => {
  const bits = '1'.repeat(i).padEnd(32, '0');
  const netmask = Array.from({ length: 4 }, (_, j) =>
    parseInt(bits.slice(j * 8, j * 8 + 8), 2)
  ).join('.');
  return { label: `/${i}`, value: netmask };
});

export const ValidIPv6 = (address: string): boolean => {
  const ipv6Regex = /^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$|^(?:[a-fA-F0-9]{1,4}:){1,7}:$|^(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}$|^(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}$|^(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}$|^(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}$|^(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}$|^[a-fA-F0-9]{1,4}:(?:(?::[a-fA-F0-9]{1,4}){1,6})$|^:(?:(?::[a-fA-F0-9]{1,4}){1,7}|:)$|^::(?:ffff(?::0{1,4}){0,1}:){0,1}(25[0-5]|(2[0-4]|1{0,1}\d|[1-9]|)\d)(\.(25[0-5]|(2[0-4]|1{0,1}\d|[1-9]|)\d)){3}$|^(?:[a-fA-F0-9]{1,4}:){1,7}:(25[0-5]|(2[0-4]|1{0,1}\d|[1-9]|)\d)(\.(25[0-5]|(2[0-4]|1{0,1}\d|[1-9]|)\d)){3}$/;
  return ipv6Regex.test(address);
};

export const IPv6CIDRs = Array.from({ length: 129 }, (_, i) => {
  const bits = '1'.repeat(i).padEnd(128, '0');
  const netmask = Array.from({ length: 8 }, (_, j) =>
    parseInt(bits.slice(j * 16, j * 16 + 16), 2).toString(16).padStart(4, '0')
  ).join(':');
  return { label: `/${i}`, value: netmask };
});