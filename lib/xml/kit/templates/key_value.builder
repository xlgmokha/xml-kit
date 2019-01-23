# frozen_string_literal: true

xml.KeyValue do
  render(rsa, xml: xml) if @rsa
end
