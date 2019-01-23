RSpec.describe Soap do
  describe '#to_xml' do
    subject { described_class.new }

    let(:result) { Hash.from_xml(subject.to_xml) }

    specify { expect(result['Envelope']).to be_present }
    specify { expect(result['Envelope']['Header']).to be_present }
    specify { expect(result['Envelope']['Body']).to be_present }
  end
end
