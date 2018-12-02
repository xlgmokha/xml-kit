# frozen_string_literal: true

require 'English'

RSpec.configure do |config|
  config.include(Module.new do
    def execute_shell(command)
      puts `#{command}`
      raise "command failed: #{command}" unless $CHILD_STATUS.success?
    end
  end)
end
