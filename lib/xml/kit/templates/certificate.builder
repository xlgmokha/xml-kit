# frozen_string_literal: true

xml.KeyDescriptor use ? { use: use } : {} do
  render key_info, xml: xml
end
