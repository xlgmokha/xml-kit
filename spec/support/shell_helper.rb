# frozen_string_literal: true

RSpec.configure do |config|
  config.include(Module.new do
    def execute_shell(command)
      puts command.inspect
      raise "command failed: #{command}" unless system(command)
    end
  end)
end
