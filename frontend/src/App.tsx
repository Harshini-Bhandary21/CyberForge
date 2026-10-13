import { Route, Routes } from "react-router-dom";
import Layout from "@/components/Layout";
import Approvals from "@/pages/Approvals";
import Behaviour from "@/pages/Behaviour";
import CodeGuard from "@/pages/CodeGuard";
import Compliance from "@/pages/Compliance";
import Dojo from "@/pages/Dojo";
import FraudGuard from "@/pages/FraudGuard";
import Incidents from "@/pages/Incidents";
import LiveGuard from "@/pages/LiveGuard";
import NotFound from "@/pages/NotFound";
import Overview from "@/pages/Overview";
import RedTeam from "@/pages/RedTeam";
import Scanner from "@/pages/Scanner";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="guard" element={<LiveGuard />} />
        <Route path="approvals" element={<Approvals />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="scanner" element={<Scanner />} />
        <Route path="behaviour" element={<Behaviour />} />
        <Route path="fraud" element={<FraudGuard />} />
        <Route path="code" element={<CodeGuard />} />
        <Route path="compliance" element={<Compliance />} />
        <Route path="redteam" element={<RedTeam />} />
        <Route path="dojo" element={<Dojo />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
