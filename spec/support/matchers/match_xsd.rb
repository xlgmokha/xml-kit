require 'rspec/expectations'

RSpec::Matchers.define :match_xsd do
  match do |actual|
    file = File.expand_path(File.join(__dir__, "../../fixtures/xsd/item.xsd"))
    xml = Nokogiri::XML(actual).document
    Dir.chdir(File.dirname(file)) do
      xsd = Nokogiri::XML::Schema(IO.read(file))
      expect(xsd.validate(xml)).to be_empty
    end
  end
end

