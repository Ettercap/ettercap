--print("Hello world!");
ettercap.ui_msg("Hello world WOOOOO!\n");

function handle_dns_packet(dns_packet)
  ettercap.ui_msg("I'm handling a DNS packet!\n");
end

function handle_http_packet(http_packet)
  ettercap.ui_msg("I'm handling an HTTP packet!\n");
end

function handle_eth_packet(eth_packet)
  ettercap.ui_msg("I'm handling an ETH packet!\n");
end
