require 'rubygems'
require 'ffi'
require 'pp'
puts "woo woo0"

begin
module Ettercap
  @@thread = nil
  @@sig_queue = Queue.new
  def self.thread=(thr)
    @@thread = thr
  end

  def self.thread
    @@thread
  end

  def self.sig_queue
    @@sig_queue
  end

  module Constants
    FINGER_LEN = 28
    MEDIA_ADDR_LEN  = 6
    IP6_ADDR_LEN    = 16
    MAX_IP_ADDR_LEN = IP6_ADDR_LEN
  end

  class Timeval < FFI::Struct
    layout :tv_sec, :time_t,
           :tv_usec, :suseconds_t
  end


  class PassiveInfo < FFI::Struct
    include Ettercap::Constants
    layout :fingerprint, [:char, FINGER_LEN + 1],
           :flags, :uint8
  end


  class IPAddrStruct < FFI::Struct
    include Ettercap::Constants

    layout :addr_type, :uint16,
           :addr_len, :uint16,
           :addr, :string
  end

  class DissectorInfo < FFI::Struct
    layout :user, :string,
           :pass, :string,
           :info, :string,
           :banner, :string,
           :failed, :char
  end



  module Packet
    class MacAddr < FFI::Struct
      include Ettercap::Constants
      layout :mac, [:uint8, MEDIA_ADDR_LEN]

      FMT = "%02x:%02x:%02x:%02x:%02x:%02x"

      def to_s
        FMT % self[:mac].to_a
      end

    end

    class L2 < FFI::Struct
      include Ettercap::Constants

      layout :proto, :uint8,
             :header, :string,
             :len, :size_t,
             :src, Ettercap::Packet::MacAddr,
             :dst, Ettercap::Packet::MacAddr 

    end

    class L3 < FFI::Struct
      include Ettercap::Constants

      layout :proto, :uint16,
             :header, :string,
             :options, :string,
             :len, :size_t,
             :payload_len, :size_t,
             :optlen, :size_t,
             :src, Ettercap::IPAddrStruct,
             :dst, Ettercap::IPAddrStruct,
             :ttl, :uint8
    end

    class L4 < FFI::Struct
      include Ettercap::Constants

      layout :proto, :uint8,
             :flags, :uint8,
             :header, :string,
             :options, :string,
             :len, :size_t,
             :optlen, :size_t,
             :src, :uint16,
             :dst, :uint16,
             :seq, :uint32,
             :ack, :uint32
    end

    class PacketData < FFI::Struct
      include Ettercap::Constants

      layout :data, :string,
             :len, :size_t,
             :disp_len, :size_t,
             :disp_data, :string,
             :delta, :int,
             :inject_len, :size_t,
             :inject, :string
    end

    class PacketStruct < FFI::Struct
      layout :ts, Ettercap::Timeval,
             :L2, Ettercap::Packet::L2,
             :L3, Ettercap::Packet::L3,
             :L4, Ettercap::Packet::L4,
             :data, Ettercap::Packet::PacketData,
             :fwd_len, :size_t,
             :fwd_packet, :string,
             :len, :size_t,
             :packet, :string,
             :ec_session, :pointer,
             :flags, :uint16,
             :DISSECTOR, Ettercap::DissectorInfo,
             :PASSIVE, Ettercap::PassiveInfo
    end
  end

end
module Ettercap
  extend FFI::Library
  ffi_lib FFI::CURRENT_PROCESS

  enum :hook_type, [
     :packet_base, 50,
     :packet_eth,
     :packet_fddi,      
     :packet_tr,
     :packet_wifi,
     :packet_arp,
     :packet_arp_rq,
     :packet_arp_rp,
     :packet_ip,
     :packet_ip6,
     :packet_udp,
     :packet_tcp,
     :packet_icmp,
     :packet_lcp,
     :packet_ecp,
     :packet_ipcp,
     :packet_ppp,
     :packet_gre,
     :packet_vlan,
     :packet_icmp6,
     :packet_icmp6_nsol,
     :packet_icmp6_nadv,
     # /* high level protocol hooks */
     :proto_base, 100,
     :proto_smb,
     :proto_smb_chl,
     :proto_smb_cmplt,
     :proto_dhcp_request,
     :proto_dhcp_discover,
     :proto_dhcp_profile,
     :proto_dns,
     :proto_nbns,
     :proto_http,
  ];

  attach_function :ui_msg, [:string], :void
  #callback :hook_callback, [:pointer], :void
  attach_function :hook_add, [:hook_type, :pointer], :int
  attach_function :hook_del, [:hook_type, :pointer], :int

  def self.create_hook(hook_type, &block)
    cb = FFI::Function.new(:void, [:pointer], :blocking => true) do |packet|
      block.call(packet)
    end
    Ettercap.hook_add(hook_type, cb)
    # Make sure we clean up at our exit...
    at_exit { self.delete_hook(hook_type, cb) }
  end

  def self.delete_hook(hook_type, cb)
    puts "deleting hook: #{hook_type}, #{cb}"
    Ettercap.hook_del(hook_type, cb)
  end

  def self.hook_udp(&block)
    create_hook(:packet_udp, &block)
  end
end
Ettercap.ui_msg("Adding callback for ETH packets\n")

Ettercap.hook_udp do |packet|
  begin
    packet_obj = Ettercap::Packet::PacketStruct.new packet
    Ettercap.ui_msg("SRC MAC: #{packet_obj[:L2][:src]}\n")
    Ettercap.ui_msg("DST MAC: #{packet_obj[:L2][:dst]}\n")
  rescue => e
    Ettercap.ui_msg("Error while parsing packet: #{e}")
  end
end
Ettercap.ui_msg("Callback added.\n")

#sleep
rescue => e
  warn "Plugin load failed: #{e}"
end
