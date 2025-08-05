import { SponsorCard } from "@/components/sponsor-card"
import { Navigation } from "@/components/navigation"
import { sponsors } from "@/data/sponsors"

export default function SponsorsPage() {
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <Navigation />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-4">Sponsors</h1>
        <p className="text-gray-600 dark:text-gray-300 mb-8 max-w-3xl">
          Blaisone is sponsored by many generous organizations, without whom we would not exist. If you would like to
          sponsor us, please reach out via email at [email protected].
        </p>

        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-8">2024</h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-12">
          {sponsors.map((sponsor, index) => (
            <SponsorCard key={index} sponsor={sponsor} />
          ))}
        </div>
      </main>
    </div>
  )
}
