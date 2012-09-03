require 'thread'
puts "In hello2!"
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


end
begin
  require 'thread'
  Ettercap.thread = Thread.new { 
    puts "HI MIKE #{RUBY_DESCRIPTION}"
    Ettercap.sig_queue.pop() 
  }
rescue => e
  puts "Error!!: #{e}"
end
puts "All done with hello2"
